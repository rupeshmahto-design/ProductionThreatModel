"""
Multi-Pass Document Analyzer for Threat Modeling
=================================================

Handles large document sets that exceed single-pass context window limits.

Architecture:
    Pass 1 (MAP):   Each document/image is analyzed individually by Claude
                    to extract security-relevant information into a condensed summary.
    
    Pass 2 (REDUCE): All condensed summaries are combined and fed into the
                     final threat assessment prompt, along with up to MAX_IMAGES
                     of the most important architecture diagrams.

This ensures no content is silently truncated or dropped, regardless of how
many documents or how large they are.
"""

import base64
import io
import logging
from typing import List, Dict, Any, Tuple, Optional
from pathlib import Path

import anthropic

from file_processor import resize_image_for_api

logger = logging.getLogger(__name__)

# --- Configuration ---
# Single-pass thresholds: if content fits within these, skip multi-pass
SINGLE_PASS_MAX_TEXT_TOKENS = 100_000
SINGLE_PASS_MAX_IMAGES = 3
CHARS_PER_TOKEN = 4

# Multi-pass settings
MAX_IMAGES_IN_FINAL_PASS = 3        # Max images to include in the final assessment
EXTRACTION_MAX_TOKENS = 4_000        # Max output tokens per document extraction
EXTRACTION_MODEL = "claude-sonnet-4-20250514"


def estimate_tokens(text: str) -> int:
    """Rough token estimate: ~4 chars per token"""
    return len(text) // CHARS_PER_TOKEN


def needs_multi_pass(text_contents: List[Dict], image_contents: List[Dict]) -> bool:
    """
    Determine whether the document set is too large for a single API call.
    
    Returns True if multi-pass is needed, False if single-pass will work.
    """
    total_text_tokens = sum(estimate_tokens(doc.get('text', '')) for doc in text_contents)
    num_images = len(image_contents)
    
    if total_text_tokens > SINGLE_PASS_MAX_TEXT_TOKENS:
        logger.info(f"📊 Multi-pass needed: {total_text_tokens:,} text tokens > {SINGLE_PASS_MAX_TEXT_TOKENS:,} limit")
        return True
    
    if num_images > SINGLE_PASS_MAX_IMAGES:
        logger.info(f"📊 Multi-pass needed: {num_images} images > {SINGLE_PASS_MAX_IMAGES} limit")
        return True
    
    logger.info(f"📊 Single-pass OK: {total_text_tokens:,} text tokens, {num_images} images")
    return False


def _extract_from_text_document(
    client: anthropic.Anthropic,
    doc_name: str,
    doc_text: str,
    project_context: str
) -> str:
    """
    Pass 1 - MAP: Extract security-relevant information from a single text document.
    
    Uses a focused prompt that asks Claude to pull out only the information
    relevant to threat modeling: components, data flows, auth mechanisms,
    integration points, sensitive data, etc.
    """
    # If document is small enough, return it as-is (no point summarizing short docs)
    if estimate_tokens(doc_text) < 2_000:
        logger.info(f"  📄 {doc_name}: small doc ({estimate_tokens(doc_text)} tokens), keeping as-is")
        return f"### {doc_name}\n{doc_text}"
    
    prompt = f"""You are a security analyst extracting threat-modeling-relevant information from a project document.

**Project Context:** {project_context}
**Document:** {doc_name}

**DOCUMENT CONTENT:**
{doc_text}

**YOUR TASK:**
Extract and summarize ALL security-relevant information from this document. Be thorough — anything you miss here will NOT be available for the threat assessment. Structure your extraction as:

1. **System Components & Architecture** — every component, service, database, API, queue, cache mentioned
2. **Data Flows & Integration Points** — how data moves between components, external APIs, third-party services
3. **Authentication & Authorization** — auth mechanisms, identity providers, token handling, session management
4. **Sensitive Data** — PII, financial data, credentials, API keys, certificates mentioned
5. **Infrastructure & Deployment** — cloud services, containers, networking, load balancers, CDNs
6. **Existing Security Controls** — encryption, firewalls, WAF, logging, monitoring mentioned
7. **Trust Boundaries** — where internal meets external, privilege escalation points
8. **Compliance & Regulatory References** — any standards, regulations, or policies mentioned
9. **Known Risks or Concerns** — anything the document flags as a risk, limitation, or technical debt

Be specific. Include names, versions, protocols, ports, and configurations. Quote exact text where important.
If a section has no relevant content, write "None identified in this document."
"""

    try:
        message = client.messages.create(
            model=EXTRACTION_MODEL,
            max_tokens=EXTRACTION_MAX_TOKENS,
            temperature=0,
            messages=[{"role": "user", "content": prompt}]
        )
        extraction = message.content[0].text
        tokens_used = estimate_tokens(extraction)
        logger.info(f"  📄 {doc_name}: extracted {tokens_used} tokens from {estimate_tokens(doc_text)} original")
        return f"### Extracted from: {doc_name}\n{extraction}"
    
    except Exception as e:
        logger.error(f"  ❌ {doc_name}: extraction failed: {e}")
        # Fallback: truncate to first 8k tokens rather than losing the doc entirely
        fallback_chars = 32_000
        truncated = doc_text[:fallback_chars]
        return f"### {doc_name} (extraction failed, showing first {fallback_chars // CHARS_PER_TOKEN}k tokens)\n{truncated}"


def _extract_from_image(
    client: anthropic.Anthropic,
    img_name: str,
    base64_data: str,
    media_type: str,
    project_context: str
) -> str:
    """
    Pass 1 - MAP: Analyze a single image (architecture diagram, data flow, etc.)
    and produce a detailed textual description for use in the final assessment.
    """
    prompt = f"""You are a security analyst examining an architecture or technical diagram for a threat assessment.

**Project Context:** {project_context}
**Image:** {img_name}

Analyze this diagram and extract ALL security-relevant information:

1. **Components Identified** — every system, service, database, user, external entity visible
2. **Data Flows** — direction of arrows, protocols, what data moves where
3. **Trust Boundaries** — any borders, zones, DMZ lines, VPC boundaries, network segments
4. **External Interfaces** — internet-facing components, third-party integrations, APIs
5. **Security Controls Visible** — firewalls, load balancers, WAFs, encryption indicators
6. **Potential Concerns** — missing security controls, exposed components, single points of failure

Be extremely detailed. This textual description will be the ONLY representation of this diagram in the final threat assessment — the image itself won't be available. Name every component, every arrow, every label you can see."""

    try:
        message = client.messages.create(
            model=EXTRACTION_MODEL,
            max_tokens=EXTRACTION_MAX_TOKENS,
            temperature=0,
            messages=[{
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt},
                    {
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": media_type,
                            "data": base64_data
                        }
                    }
                ]
            }]
        )
        extraction = message.content[0].text
        logger.info(f"  🖼️  {img_name}: extracted {estimate_tokens(extraction)} tokens from image")
        return f"### Architecture Diagram Analysis: {img_name}\n{extraction}"
    
    except Exception as e:
        logger.error(f"  ❌ {img_name}: image analysis failed: {e}")
        return f"### {img_name}\n[Image could not be analyzed: {str(e)[:100]}]"


def _select_priority_images(image_files: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
    """
    Select the most important images to include visually in the final pass.
    
    Priority heuristic:
    - Architecture/system diagrams > screenshots > generic images
    - Larger images (more detail) > smaller ones
    - First MAX_IMAGES_IN_FINAL_PASS are selected for visual inclusion
    """
    # Score images by filename heuristic
    def priority_score(img: Dict) -> int:
        name = img.get('name', '').lower()
        score = 0
        # Architecture-related keywords get highest priority
        if any(kw in name for kw in ['arch', 'system', 'infrastructure', 'network', 'topology']):
            score += 10
        if any(kw in name for kw in ['flow', 'data', 'sequence', 'diagram']):
            score += 8
        if any(kw in name for kw in ['deploy', 'cloud', 'aws', 'azure', 'gcp']):
            score += 6
        if any(kw in name for kw in ['security', 'threat', 'risk', 'trust']):
            score += 5
        # Penalize screenshots and generic names
        if any(kw in name for kw in ['screenshot', 'screen', 'photo', 'img_']):
            score -= 3
        return score
    
    sorted_images = sorted(image_files, key=priority_score, reverse=True)
    
    visual_images = sorted_images[:MAX_IMAGES_IN_FINAL_PASS]
    text_only_images = sorted_images[MAX_IMAGES_IN_FINAL_PASS:]
    
    if text_only_images:
        logger.info(f"🖼️  Selected {len(visual_images)} priority images for visual inclusion, "
                     f"{len(text_only_images)} will be text-described only")
    
    return visual_images, text_only_images


def prepare_documents_multi_pass(
    client: anthropic.Anthropic,
    files_data: List[Dict],
    project_name: str,
    application_type: str = "Web Application",
    progress_callback=None
) -> Tuple[str, List[Dict], Dict]:
    """
    Main entry point for multi-pass document processing.
    
    Args:
        client: Anthropic client instance
        files_data: List of {'name': str, 'content': str|bytes} dicts
        project_name: Project name for context
        application_type: Type of application being assessed
        progress_callback: Optional callable(step: str, progress: float) for UI updates
    
    Returns:
        Tuple of:
            - documents_content: str — condensed text content for the final prompt
            - image_content: list — image data dicts for visual inclusion in final pass
            - metadata: dict — processing stats
    """
    project_context = f"{project_name} ({application_type})"
    
    # ── Step 1: Separate text documents from images ──
    text_docs = []
    image_docs = []
    
    for file_data in files_data:
        filename = file_data.get('name', 'unknown')
        content = file_data.get('content', b'')
        ext = Path(filename).suffix.lower().lstrip('.')
        
        if ext in ['png', 'jpg', 'jpeg', 'gif', 'webp']:
            # Prepare image data
            if isinstance(content, str):
                base64_data = content
                if base64_data.startswith('data:'):
                    if ';base64,' in base64_data:
                        base64_data = base64_data.split(';base64,', 1)[1]
                # Decode, resize, re-encode
                try:
                    raw_bytes = base64.b64decode(base64_data)
                    raw_bytes = resize_image_for_api(raw_bytes)
                    base64_data = base64.standard_b64encode(raw_bytes).decode('utf-8')
                except Exception:
                    pass  # Use original if resize fails
            else:
                content = resize_image_for_api(content)
                base64_data = base64.standard_b64encode(content).decode('utf-8')
            
            media_type_map = {
                'jpg': 'image/jpeg', 'jpeg': 'image/jpeg',
                'png': 'image/png', 'gif': 'image/gif', 'webp': 'image/webp'
            }
            
            image_docs.append({
                'name': filename,
                'base64': base64_data,
                'media_type': media_type_map.get(ext, 'image/jpeg')
            })
        else:
            # Extract text from file
            from file_processor import process_file
            text = process_file(filename, content if isinstance(content, bytes) else content.encode('utf-8'))
            text_docs.append({
                'name': filename,
                'text': text,
                'tokens': estimate_tokens(text)
            })
    
    total_text_tokens = sum(d['tokens'] for d in text_docs)
    total_images = len(image_docs)
    
    logger.info(f"📊 Document inventory: {len(text_docs)} text docs ({total_text_tokens:,} tokens), {total_images} images")
    
    # ── Step 2: Decide single-pass vs multi-pass ──
    if not needs_multi_pass(text_docs, image_docs):
        # Single pass — return content as-is for the existing flow
        logger.info("✅ Using single-pass processing")
        from file_processor import process_files_with_vision
        return process_files_with_vision(files_data)
    
    # ── Step 3: Multi-pass MAP phase ──
    logger.info(f"🔄 Starting multi-pass MAP phase ({len(text_docs)} text + {total_images} images)...")
    
    extracted_sections = []
    total_steps = len(text_docs) + total_images
    current_step = 0
    
    # 3a: Extract from each text document
    for doc in text_docs:
        current_step += 1
        if progress_callback:
            progress_callback(
                f"Analyzing document {current_step}/{total_steps}: {doc['name']}",
                current_step / total_steps
            )
        
        logger.info(f"  [{current_step}/{total_steps}] Analyzing: {doc['name']} ({doc['tokens']:,} tokens)")
        extraction = _extract_from_text_document(
            client, doc['name'], doc['text'], project_context
        )
        extracted_sections.append(extraction)
    
    # 3b: Analyze each image
    for img in image_docs:
        current_step += 1
        if progress_callback:
            progress_callback(
                f"Analyzing diagram {current_step}/{total_steps}: {img['name']}",
                current_step / total_steps
            )
        
        logger.info(f"  [{current_step}/{total_steps}] Analyzing image: {img['name']}")
        extraction = _extract_from_image(
            client, img['name'], img['base64'], img['media_type'], project_context
        )
        extracted_sections.append(extraction)
    
    # ── Step 4: Prepare final content for REDUCE phase ──
    
    # Combine all extracted text
    combined_text = "\n\n---\n\n".join(extracted_sections)
    combined_tokens = estimate_tokens(combined_text)
    
    logger.info(f"📦 MAP phase complete: {combined_tokens:,} tokens from {total_steps} sources")
    
    # Select priority images for visual inclusion in final pass
    visual_images, text_only_images = _select_priority_images(image_docs)
    
    # Build image content list for the final API call (same format as process_files_with_vision)
    final_image_content = []
    for img in visual_images:
        final_image_content.append({
            'name': img['name'],
            'data': {
                'type': 'image',
                'source': {
                    'type': 'base64',
                    'media_type': img['media_type'],
                    'data': img['base64']
                }
            },
            'type': 'image'
        })
    
    # Build metadata
    metadata = {
        'processing_mode': 'multi_pass',
        'total_files': len(text_docs) + total_images,
        'text_documents': len(text_docs),
        'total_images': total_images,
        'images_visual': len(visual_images),
        'images_text_only': len(text_only_images),
        'original_text_tokens': total_text_tokens,
        'extracted_text_tokens': combined_tokens,
        'compression_ratio': f"{total_text_tokens / max(combined_tokens, 1):.1f}x",
        'map_api_calls': total_steps,
        'image_files': [img['name'] for img in image_docs]
    }
    
    logger.info(f"📊 Multi-pass summary: {total_text_tokens:,} → {combined_tokens:,} tokens "
                f"({metadata['compression_ratio']} compression), "
                f"{len(final_image_content)} visual images included")
    
    if progress_callback:
        progress_callback("Document analysis complete, generating assessment...", 1.0)
    
    return combined_text, final_image_content, metadata
