from pyFireEye.hx import HX

# initialize the bindings object
hx = HX(hx_host="https://fireeyehx.hooli.org", hx_port=None, verify=False, token_auth=False, username="", password="")
# verify toggles https certificate verification, and token_auth toggles whether to use basic or token authentication
# username and password should be self explanatory

# if you do not provide username and password on init, you will need to call authenticate
hx.authenticate(username="gavin", password="DestroyPP")  # token_auth can be set here as well


# to get a list of hosts in the system
host_lists = hx.hosts.get_list_of_hosts().entries

# since hx paginates its responses (default 50 at a time),
# get the first 10000 hosts
host_lists = hx.hosts.get_list_of_hosts(limit=10000, offset=0).entries

