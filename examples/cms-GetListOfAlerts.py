from pyFireEye.cms import CMS

cms = CMS(cms_host="https://localhost", cms_port=443, verify=False, token_auth=True, username="api-acc", password="test")
alerts = cms.alerts.get_alerts()
print(alerts)
