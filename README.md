# dnsmapper
A tool to create a simple map of a specific domain dns records
# Example
`python3 dnsmapper.py -d google.com -v -a -n`<br/>
It will take about 30 seconds to finish<br/>
# The Result
For yahoo.com the result should look like this:<br/><br/>
![Alt text](https://i.imgur.com/G0hT5Oy.png)
# How to import
`import dnsmapper`<br/>
`dnsmapper.init_all(extract_subdomains_from_any_return=True,verbous=True)`<br/>
`ret = dnsmapper.main("google.com")`<br/>
`print(ret[0])`<br/>
`print("return_ipv4 = {}".format(ret[1]))`<br/>
`print("return_ipv6 = {}".format(ret[2]))`<br/>
# ToDo
Extract IPv4 & IPv6 from any return data and passing them through the loop
