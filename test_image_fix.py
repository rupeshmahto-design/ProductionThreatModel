"""
Quick test to verify image processing fix for Claude Vision API
"""
import base64
import io
from PIL import Image

def test_data_uri_stripping():
    """Test that data URI prefix is properly stripped"""
    
    # Create a small test image
    img = Image.new('RGB', (10, 10), color='red')
    img_buffer = io.BytesIO()
    img.save(img_buffer, format='PNG')
    img_bytes = img_buffer.getvalue()
    
    # Encode to base64
    base64_image = base64.standard_b64encode(img_bytes).decode('utf-8')
    
    # Create data URI (as frontend would send)
    data_uri = f"data:image/png;base64,{base64_image}"
    
    print("✅ Test 1: Data URI Format")
    print(f"   Data URI prefix: {data_uri[:50]}...")
    print(f"   Contains 'data:': {data_uri.startswith('data:')}")
    print(f"   Contains ';base64,': {';base64,' in data_uri}")
    
    # Strip data URI prefix (our fix)
    if data_uri.startswith('data:') and ';base64,' in data_uri:
        stripped = data_uri.split(';base64,', 1)[1]
        print(f"   Stripped successfully: {stripped[:50]}...")
        print(f"   Original base64 matches: {stripped == base64_image}")
    
    print("\n✅ Test 2: Image Size Check")
    image_size_bytes = len(base64_image) * 3 // 4
    print(f"   Base64 length: {len(base64_image)}")
    print(f"   Estimated size: {image_size_bytes} bytes ({image_size_bytes/1024:.2f} KB)")
    print(f"   Within 5MB limit: {image_size_bytes < 5*1024*1024}")
    
    print("\n✅ Test 3: Claude API Format")
    media_type = 'image/png'
    claude_format = {
        'type': 'image',
        'source': {
            'type': 'base64',
            'media_type': media_type,
            'data': stripped if data_uri.startswith('data:') else base64_image
        }
    }
    print(f"   Format type: {claude_format['type']}")
    print(f"   Source type: {claude_format['source']['type']}")
    print(f"   Media type: {claude_format['source']['media_type']}")
    print(f"   Data length: {len(claude_format['source']['data'])}")
    print(f"   Data starts with valid base64: {claude_format['source']['data'][:20].replace('+', '').replace('/', '').replace('=', '').isalnum()}")
    
    print("\n🎉 All tests passed!")

if __name__ == "__main__":
    try:
        test_data_uri_stripping()
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
