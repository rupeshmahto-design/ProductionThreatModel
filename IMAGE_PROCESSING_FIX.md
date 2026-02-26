# Image Processing Fix - Claude Vision API Error

## Problem
The application was experiencing `400 Bad Request` errors from Claude API with the message:
```
Error code: 400 - {'type': 'error', 'error': {'type': 'invalid_request_error', 'message': 'Could not process image'}}
```

This occurred when users uploaded images (PNG, JPG, etc.) for threat modeling analysis.

## Root Cause
When the frontend sent images as base64-encoded data, they included the **data URI prefix** (e.g., `data:image/png;base64,`). The Claude Vision API expects **only the raw base64-encoded image data** without this prefix.

Example of what was being sent:
```
data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAoAAAAKCAI...
```

What Claude API expects:
```
iVBORw0KGgoAAAANSUhEUgAAAAoAAAAKCAI...
```

## Solution
Updated [file_processor.py](file_processor.py#L345-L360) to automatically detect and strip the data URI prefix before sending images to Claude API:

### Changes Made:

1. **Data URI Prefix Stripping** (Lines 345-360)
   - Detects if base64 string starts with `data:`
   - Extracts only the base64 data after `;base64,`
   - Logs the operation for debugging

2. **Image Validation** (Lines 367-370)
   - Validates that base64 data is not empty
   - Skips invalid images gracefully

3. **Size Limit Enforcement** (Lines 372-375)
   - Checks images don't exceed 5MB (Claude API limit)
   - Prevents API errors from oversized images

4. **Enhanced Logging** (Lines 383-384)
   - Logs media type and size for each image
   - Helps debug future issues

## Testing
Created [test_image_fix.py](test_image_fix.py) which verifies:
- ✅ Data URI prefix is correctly stripped
- ✅ Base64 data remains valid after stripping
- ✅ Image size calculation works correctly
- ✅ Claude API format structure is correct

All tests pass successfully.

## Impact
- Users can now upload images (diagrams, architecture drawings) without errors
- Images are properly processed by Claude Vision API for threat analysis
- Better error handling prevents invalid images from causing 500 errors

## Deployment
The fix is backward compatible and requires no database migrations or configuration changes. Simply restart the application to apply the fix.

## Next Steps
Monitor production logs for:
- Image processing success rate
- Any remaining "Could not process image" errors
- Image size warnings (>5MB)
