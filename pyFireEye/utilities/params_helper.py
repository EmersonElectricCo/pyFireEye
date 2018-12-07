# HX Params
# common params
LIMIT = "limit"
OFFSET = "offset"
SEARCH = "search"
SORT = "sort"
FILTER_FIELD = "filter_field"

HAS_ACTIVE_THREATS = "has_active_threats"
HAS_ALERTS = "has_alerts"
HAS_EXECUTION_ALERTS = "has_execution_alerts"
HAS_EXPLOIT_ALERTS = "has_exploit_alerts"
HAS_EXPLOIT_BLOCKS = "has_exploit_blocks"
HAS_MALWARE_ALERTS = "has_malware_alerts"
HAS_MALWARE_CLEANED = "has_malware_cleaned"
HAS_MALWARE_QUARANTINED = "has_malware_quarantined"
HAS_PRESENCE_ALERTS = "has_presence_alerts"
HAS_SHARE_MODE = "has_share_mode"
HOSTS_SET_ID = "host_sets.id"

# Indicators
CATEGORY_SHARE_MODE = "category.share_mode"

# Conditions
ENABLED = "enabled"  # bool

# Indicator categories
SHARE_MODE = "share_mode"

# Alerts
RESOLUTION = "resolution"

# Source Alerts
PRIMARY_INDICATOR_ID = "primary_indicator.id"
FILTER_QUERY = "filterQuery"
# Containment
STATE_UPDATE_TIME = "state_update_time"


# IF YOU NEED TO USE ONE OF THE PARAMETERS IN THIS DICTIONARY, USE THE REPLACEMENT
param_arg_map = {
    "host_set_id": HOSTS_SET_ID,
    "category_share_mode": CATEGORY_SHARE_MODE,
    "primary_indicator_id": PRIMARY_INDICATOR_ID
}

# AX/CM Params
# ALERTS
ALERT_ID = "alert_id"
CALLBACK_DOMAIN = "callback_domain"  # CM ONLY
DST_IP = "dst_ip"  # CM ONLY
SRC_IP = "src_ip"  # CM ONLY
DURATION = "duraion"
END_TIME = "end_time"
FILE_NAME = "file_name"
FILE_TYPE = "file_type"
INFO_LEVEL = "info_level"
MALWARE_NAME = "malware_name"
MALWARE_TYPE = "malware_type"
MD5 = "md5"
RECIPIENT_EMAIL = "recipient_email"
SENDER_EMAIL = "sender_email"
START_TIME = "start_time"
URL = "url"

# REPORTS
REPORT_TYPE = "report_type"
INFECTION_ID = "infection_id"
INFECTION_TYPE = "infection_type"
ID = "id"

# SUBMISSIONS
APPLICATION = "application"
TIMEOUT = "timeout"
PRIORITY = "priority"
PROFILES = "profiles"
ANALYSISTYPE = "analysistype"
FORCE = "force"
PREFETCH = "prefetch"
URLS = "urls"
