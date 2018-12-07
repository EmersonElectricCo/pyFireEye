from pyFireEye.ax import AX

# initialize the bindings object
ax = AX(ax_host="https://feax.hooli.com", ax_port=None, verify=False, token_auth=False, username="", password="")

submission = ax.submissions.submit_file_for_analysis(application=0, timeout=600, priority=0, profiles="someProfile",
                                                        analysistype=2,
                                                        force=False, prefetch=0, file_path="/path/to/file")


