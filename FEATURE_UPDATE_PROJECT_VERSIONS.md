# Feature Enhancement Summary - Project Number & Version History

## Date: January 29, 2026

## Changes Implemented

### 1. **Project Number Field Added to Assessments** ✅
- **Database Changes:**
  - Added `project_number` column to `ThreatAssessment` model in [models.py](models.py#L219)
  - Created indexed column for efficient querying
  - Migration applied successfully to database

- **UI Changes:**
  - Added "Project Number" input field to the assessment form in [app.py](app.py#L1607)
  - Optional field with placeholder "PRJ-2026-001"
  - Includes helpful tooltip for users
  - Form state properly managed across sessions

### 2. **Version History Grouped by Project Number** ✅
- **New View Mode:**
  - Added radio button toggle in "Past Assessments" tab
  - Two view modes:
    - 📋 **All Assessments** - Standard list view (existing functionality)
    - 📊 **Group by Project Number** - NEW version history view

- **Version History Features:**
  - Assessments grouped by project number
  - Shows version count per project
  - Latest assessment date displayed in project header
  - Each version numbered (Version 1, 2, 3, etc.)
  - Chronological ordering with newest first
  - Full metadata for each version:
    - Creation date and time
    - Framework used
    - Status
    - Risk areas
    - Risk metrics (Critical/High/Medium counts)

- **Enhanced UX:**
  - Professional gradient headers for each project group
  - Collapsible version cards (latest version expanded by default)
  - Side-by-side comparison-ready layout
  - Individual download buttons (PDF & Markdown) per version
  - Full report viewing in expandable sections

### 3. **Date Bug Fixed** ✅
- **Issue:** Reports were not showing current date correctly
- **Solution:**
  - Updated PDF generation to use `datetime.now()` with current system time
  - Added timezone support for Sydney, Australia (`Australia/Sydney`)
  - Updated both PDF and Markdown download filenames
  - Graceful fallback to UTC if timezone not available

- **Files Modified:**
  - [app.py](app.py#L6) - Added `zoneinfo` import
  - [app.py](app.py#L896-L910) - Updated `create_pdf_download()` function
  - [app.py](app.py#L962) - Updated PDF date field
  - [app.py](app.py#L1768-L1774) - Updated Markdown download date

### 4. **Metric Updates** ✅
- Changed 4th metric in Past Assessments from "Frameworks Used" to "🔢 Unique Projects"
- Now tracks count of unique project numbers across all assessments

## Technical Implementation

### Database Schema Changes
```sql
ALTER TABLE threat_assessments 
ADD COLUMN project_number VARCHAR(100);

CREATE INDEX ix_threat_assessments_project_number 
ON threat_assessments (project_number);
```

### Key Code Changes

**1. Assessment Form ([app.py](app.py#L1607))**
```python
project_number = st.text_input(
    "Project Number", 
    placeholder="e.g., PRJ-2026-001", 
    key="project_number", 
    help="Optional: Project number for version tracking"
)
```

**2. Assessment Storage ([app.py](app.py#L1380))**
```python
assessment = ThreatAssessment(
    # ... other fields ...
    project_number=project_info.get('number', None),
    # ... other fields ...
)
```

**3. Version History View ([app.py](app.py#L1810-L1830))**
```python
# Group assessments by project number
from collections import defaultdict
project_groups = defaultdict(list)

for assessment in filtered_assessments:
    proj_num = assessment.project_number if assessment.project_number else "No Project Number"
    project_groups[proj_num].append(assessment)
```

## User Guide

### Creating an Assessment with Project Number:
1. Navigate to "Threat Modeling" tab
2. Fill in "Project Name" (required)
3. Fill in "Project Number" (optional) - e.g., "PRJ-2026-001"
4. Complete other required fields
5. Generate assessment as usual

### Viewing Version History:
1. Navigate to "Past Assessments" tab
2. Select view mode: "📊 Group by Project Number"
3. Each project displays:
   - Project number and version count
   - Latest assessment date
   - Expandable version cards
   - Download options for each version

### Benefits:
- **Track Project Evolution:** See how threats change over time
- **Version Comparison:** Easily compare different assessment versions
- **Project Organization:** Group related assessments together
- **Audit Trail:** Complete history with dates for compliance
- **Date Accuracy:** Reports now show correct current date

## Files Modified

1. **[models.py](models.py)** - Added `project_number` field to ThreatAssessment model
2. **[app.py](app.py)** - Multiple updates:
   - Assessment form UI
   - Version history view
   - Date handling with timezone support
   - Metric calculations
3. **[alembic/versions/20260129_add_project_number.py](alembic/versions/20260129_add_project_number.py)** - New migration file
4. **[run_migration.py](run_migration.py)** - Migration helper script (can be deleted after deployment)

## Testing Recommendations

1. ✅ Create a new assessment with a project number
2. ✅ Create multiple assessments with the same project number
3. ✅ View assessments in "Group by Project Number" mode
4. ✅ Verify version numbering is correct
5. ✅ Download PDF and verify date shows January 29, 2026 (or current date)
6. ✅ Test without project number (should group under "No Project Number")
7. ✅ Test filtering works in both view modes

## Notes

- Existing assessments without project numbers will appear under "No Project Number" group
- Project numbers are optional - users can continue without them
- Timezone defaults to Australia/Sydney, falls back to UTC if unavailable
- All dates now show correct current date in reports
- Version numbers are calculated dynamically based on creation order

## Future Enhancements (Optional)

- Add project number to filters
- Export version comparison reports
- Add version diff/change highlighting
- Bulk update project numbers for existing assessments
- Project-level analytics dashboard
