# NIST_STEPS.py

NIST_STEPS = {
    "normal": {
        "analyst": [
            {"nist_phase": "Identify", "sub_step": "1", "description": "Initial detection & evidence collection",
             "required_fields": ["notes", "text", "file"]},
            {"nist_phase": "Protect", "sub_step": "2", "description": "Mitigation & temporary measures",
             "required_fields": ["notes", "text"]},
        ],
        "senior_analyst": [
            {"nist_phase": "Detect", "sub_step": "3", "description": "Validation & analysis",
             "required_fields": ["notes", "text", "file"]},
            {"nist_phase": "Respond", "sub_step": "4", "description": "Final remediation",
             "required_fields": ["notes", "text"]},
        ],
        "admin": [
            {"nist_phase": "Recover", "sub_step": "5", "description": "Post-mortem & reporting",
             "required_fields": ["notes", "text"]},
        ]
    },
    "malware": {
        "senior_analyst": [
            {"nist_phase": "Identify", "sub_step": "1", "description": "Confirm malware detection",
             "required_fields": ["notes", "text", "file"]},
            {"nist_phase": "Contain", "sub_step": "2", "description": "Isolate infected hosts",
             "required_fields": ["notes", "text", "file"]},
            {"nist_phase": "Eradicate", "sub_step": "3", "description": "Remove malware & threats",
             "required_fields": ["notes", "text", "file"]},
        ],
        "admin": [
            {"nist_phase": "Recover", "sub_step": "4", "description": "System recovery & reporting",
             "required_fields": ["notes", "text"]},
            {"nist_phase": "Lessons Learned", "sub_step": "5", "description": "Post-incident review",
             "required_fields": ["notes", "text"]},
        ]
    }
}
