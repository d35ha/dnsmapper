# coding: utf-8

from string import punctuation
import argparse
import inspect
import socket
import random
import struct
import sys
import os
import re

if not sys.version.startswith('3'):
  print("Run with python3")
  exit()

try:
  from dns.resolver import get_default_resolver
  from colorama import Fore, Back, Style
  from dns.rdatatype import is_metatype
  from dns.rdataclass import is_metaclass
  from dns import reversename
  from colorama import init
  import dns.exception
  import dns.rdatatype
  import dns.name
  import dns.message
  import dns.query
  import dns.flags
except:
  print("Install colorama and dnspython modules using pip3")
  exit()

init()
already_done = {}
maximum_recursion_depth = 20
name_servers = {'8.8.8.8':None,'8.8.4.4':None,'208.67.222.222':None,'208.67.220.220':None}
for name_server in get_default_resolver().nameservers:
  name_servers[name_server] = None

ADDITIONAL_RDCLASS = 65535


all_ids = ['NONE', 'A', 'NS', 'MD', 'MF', 'CNAME', 'SOA', 'MB', 'MG', 'MR', 'NULL', 'WKS', 
    'PTR', 'HINFO', 'MINFO', 'MX', 'TXT', 'RP', 'AFSDB', 'X25', 'ISDN', 'RT', 'NSAP',
    'NSAP-PTR', 'SIG', 'KEY', 'PX', 'GPOS', 'AAAA', 'LOC', 'NXT', 'SRV', 'NAPTR', 'KX',
    'CERT', 'A6', 'DNAME', 'OPT', 'APL', 'DS', 'SSHFP', 'IPSECKEY', 'RRSIG', 'NSEC',
    'DNSKEY', 'DHCID', 'NSEC3', 'NSEC3PARAM', 'TLSA', 'HIP', 'CDS', 'CDNSKEY', 'CSYNC',
    'SPF', 'UNSPEC', 'EUI48', 'EUI64', 'TKEY', 'TSIG', 'IXFR', 'AXFR', 'MAILB', 'MAILA',
    'ANY', 'URI', 'CAA', 'TA', 'DLV']


class SendDNSPkt:
  def __init__(self,url,serverIP,port):
    self.url=url
    self.serverIP = serverIP
    self.port=port
  def sendPkt(self):
    pkt=self._build_packet()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1)
    sock.sendto(bytes(pkt), (self.serverIP, self.port))
    data, addr = sock.recvfrom(1024)
    sock.close()
    return data
  def _build_packet(self):
    randint = random.randint(0, 65535)
    packet = struct.pack(">H", randint)  # Query Ids (Just 1 for now)
    packet += struct.pack(">H", 0x0100)  # Flags
    packet += struct.pack(">H", 1)  # Questions
    packet += struct.pack(">H", 0)  # Answers
    packet += struct.pack(">H", 0)  # Authorities
    packet += struct.pack(">H", 0)  # Additional
    split_url = self.url.split(".")
    for part in split_url:
      packet += struct.pack("B", len(part))
      for s in part:
        packet += struct.pack('c',s.encode())
    packet += struct.pack("B", 0)  # End of String
    packet += struct.pack(">H", 1)  # Query Type
    packet += struct.pack(">H", 1)  # Query Class
    return packet

def checkDNSudpPortOpen(server,port):
    s = SendDNSPkt('www.google.com', server, port)
    portOpen = False
    for _ in range(TIMEOUT):
        try:
            s.sendPkt()
            portOpen = True
            break
        except socket.timeout:
            pass
    if portOpen:
        return True
    else:
        return False

def prepare_rdata(rdata_item):
  if rdata_item.endswith("."):
    rdata_item = "".join(list(rdata_item)[:len(rdata_item) - 1])
  return rdata_item

def test_tcp_connection(host,port):
  if VERBOUS:
    erase_last_line()
    exec(r'''print("Testing tcp connection to {}:{} ...".format(host,port), end="\r")''')
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.settimeout(TIMEOUT)
  try:
    result = sock.connect_ex((host,port))
  except:
    return False
  sock.close()
  if result != 0:
    return False
  return True

def test_udp_connection(host,port):
  if VERBOUS:
    erase_last_line()
    exec(r'''print("Testing udp connection to {}:{} ...".format(host,port), end="\r")''')
  try:
    if checkDNSudpPortOpen(host,port):
      return True
    else:
      return False
  except:
    return False

def extract_axfr_from_ns_record_data(domain,servers):
  return_data = {}
  if not QUERY_NS_SERVERS_FOR_AXFR_OF_OWN_DOMAIN:
    return return_data
  answer = []
  request = dns.message.make_query(domain, dns.rdatatype._by_text["AXFR"])
  request.flags |= dns.flags.AD | dns.flags.RD | dns.flags.RA
  request.find_rrset(request.additional, dns.name.root, ADDITIONAL_RDCLASS, dns.rdatatype.OPT, create=True, force_unique=True)
  
  for server in servers:
    server = server.lower()
    if test_tcp_connection(server,53):
      if VERBOUS:
        erase_last_line()
        exec(r'''print("Querying {} from {} using tcp connection ...".format(domain,server), end="\r")''')
      try:
        response = dns.query.tcp(request, server, timeout=TIMEOUT)
        answer += [str(i) for i in response.answer]
      except:
        pass
    elif test_udp_connection(server,53):
      if VERBOUS:
        erase_last_line()
        exec(r'''print("Querying {} from {} using udp connection ...".format(domain,server), end="\r")''')
      try:
        response = dns.query.tcp(request, server, timeout=TIMEOUT)
        answer += [str(i) for i in response.answer]
      except:
        pass
    else:
      continue
  if len(answer) > 0:
    for i in range(len(answer)):
      answer[i] = color_rdata(answer[i])
    return_data["AXFR_FROM_NS"] = [color_structure("--------[NEW][AXFR] --->") + " " + str(color_structure("[NEW][AXFR] --->") + " ").join(list(set(answer))).replace("\n",color_structure("[NEW][AXFR] --->") + " ")]
  return return_data

def extract_record_data(domain, rdtype):
  rdtype = rdtype.upper()
  domain = domain.lower()
  return_data = {}
  try:
    r = dns.rdatatype._by_text[rdtype]
  except:
    return return_data
  if is_metatype(r) or is_metaclass(r):
    if domain in list(already_done.keys()):
      return already_done.get(domain)
    request = dns.message.make_query(domain, dns.rdatatype._by_text[rdtype])
    request.flags |= dns.flags.RA | dns.flags.AD
    request.find_rrset(request.additional, dns.name.root, ADDITIONAL_RDCLASS, dns.rdatatype.OPT, create=True, force_unique=True)
    for name_server in list(name_servers.keys()):
      try:
        if not IDS_ONE_BY_ONE or rdtype != "ANY":
          if name_servers.get(name_server):
            if VERBOUS:
              erase_last_line()
              exec(r'''print("Querying {} from {} using tcp connection ...".format(domain,name_server), end="\r")''')
            response = dns.query.tcp(request, name_server, timeout=TIMEOUT)
          else:
            if name_servers.get(name_server) != None:
              if VERBOUS:
                erase_last_line()
                exec(r'''print("Querying {} from {} using udp connection ...".format(domain,name_server), end="\r")''')
              response = dns.query.udp(request, name_server, timeout=TIMEOUT)
            else:
              continue
          for record_data in response.answer:
            if dns.rdatatype.to_text(record_data.rdtype) in list(return_data.keys()):
              return_data[dns.rdatatype.to_text(record_data.rdtype)] = list(set([prepare_rdata(str(s)) for s in record_data] + return_data.get(dns.rdatatype.to_text(record_data.rdtype))))
            else:
              return_data[dns.rdatatype.to_text(record_data.rdtype)] = [prepare_rdata(str(s)) for s in record_data]
        else:
          if VERBOUS:
            erase_last_line()
            exec(r'''print("Querying {} from {} ... {}".format(domain, name_server, get_progress(0, len(all_ids))), end="\r")''')
          for a in all_ids:
            try:
              if a in list(return_data.keys()):
                return_data[a] = list(set(return_data.get(a) + [prepare_rdata(str(s)) for s in get_record(domain, a)]))
              else:
                return_data[a] = [prepare_rdata(str(s)) for s in get_record(domain, a)]
            except:
              pass
            if VERBOUS:
              erase_last_line()
              exec(r'''print("Querying {} from {} ... {}".format(domain, name_server, get_progress(all_ids.index(a) + 1, len(all_ids))), end="\r")''')
      except:
        pass
  else:
    if VERBOUS:
      erase_last_line()
      exec(r'''print("Querying {} for {} ...".format(domain,rdtype), end="\r")''')
    try:
      if "[MONO]{}[MONO]".format(domain) in list(already_done.keys()):
        if rdtype in list(already_done.get("[MONO]{}[MONO]".format(domain)).keys()):
          return {rdtype: already_done.get("[MONO]{}[MONO]".format(domain)).get(rdtype)}
      if domain in list(already_done.keys()):
        if rdtype in list(already_done.get(domain).keys()):
          return {rdtype: already_done.get(domain).get(rdtype)}
      return_data = {rdtype:[prepare_rdata(str(s)) for s in get_record(domain, rdtype)]}
      domain = "[MONO]{}[MONO]".format(domain)
    except:
      return {}
  if domain in list(already_done.keys()):
    already_done[domain] = dict(already_done.get(domain), **return_data)
  else:
    already_done[domain] = return_data
  if "NS" in list(return_data.keys()):
    return_data = dict(return_data, **extract_axfr_from_ns_record_data(domain.replace("[MONO]",""),return_data.get("NS")))
  return return_data

def get_progress(iteration, total, decimals=1, bar_length=70):
    str_format = "{0:." + str(decimals) + "f}"
    percents = str_format.format(100 * (iteration / float(total)))
    filled_length = int(round(bar_length * iteration / float(total)))
    bar = '>' * filled_length + '-' * (bar_length - filled_length)
    return '|%s| %s%s' % (bar, percents, '%')
    
def get_max(i_list):
  i_list = list(i_list)
  max_l = 0
  for item in i_list:
    item = str(item)
    if len(item) > max_l:
      max_l = len(item)
  return max_l

def reverse_lookup(ip):
  try:
    return extract_record_data(prepare_rdata(str(reversename.from_address(ip))),"PTR").get("PTR")[0]
  except Exception as err:
    return "ERROR: " + "CANNOT RESOLVE"

def extract_subs(string):
  subs = []
  if not EXTRACT_SUBDOMAINS_FROM_ANY_RETURN:
    return subs
  pattern = r'^([A-Za-z0-9]\.|[A-Za-z0-9][A-Za-z0-9-]{0,61}[A-Za-z0-9]\.){1,10}[A-Za-z]{2,6}$'
  bad_chars = list(set(punctuation)) + ["\n"]
  bad_chars.remove("-")
  bad_chars.remove(".")
  bad_chars.append(".-")
  bad_chars.append("-.")
  for char in bad_chars:
    string = string.replace(char," ")
  for item in string.split(" "):
    while True:
      if item.endswith(".") or item.endswith("-"):
        item = "".join(list(item)[:len(item) - 1])
        continue
      if item.startswith(".") or item.startswith("-"):
        item = "".join(list(item)[1:])
        continue
      break
    if re.match(pattern, item.lower()):
      subs.append(item.lower())
  return list(set(subs))

def get_line_number(data,string):
  lines = data.split("\n")
  for line in lines:
    if string in line:
      return lines.index(line) + 1

def erase_last_line():
  sys.stdout.write("\033[F\x1b[2K")

def color_structure(string):
  string = Fore.YELLOW + string + Fore.RESET
  string = Style.BRIGHT + string + Style.RESET_ALL
  return string

def color_domain(string):
  string = Fore.RED + string + Fore.RESET
  string = Style.BRIGHT + string + Style.RESET_ALL
  return string

def color_records(string):
  string = Fore.BLUE + string + Fore.RESET
  string = Style.BRIGHT + string + Style.RESET_ALL
  return string

def color_rdata(string):
  return string

def parse_rdata(domain, rdata_item, record, max4, max6, rbase):

  global ip_4
  global ip_6

  if record == "A":
    original_rdata_item = rdata_item
    ip_4.append(rdata_item)
    host = reverse_lookup(rdata_item)
    if host.startswith("ERROR: "):
      return color_rdata(rdata_item) + " " + color_structure("─") * (max4 - len(rdata_item) + 1) + " " + color_domain("[{}]".format(host.split("ERROR: ")[1]))
    if domain == host:
      return color_rdata(rdata_item)
    rdata_item = color_rdata(rdata_item) + " " + color_structure("─") * (max4 - len(rdata_item) + 1) + " "
    return rdata_item + get_records(host, rbase, "", original_rdata_item)
  elif record == "AAAA":
    original_rdata_item = rdata_item
    ip_6.append(rdata_item)
    host = reverse_lookup(rdata_item)
    if host.startswith("ERROR: "):
      return color_rdata(rdata_item) + " " + color_structure("─") * (max6 - len(rdata_item) + 1) + " " + color_domain("[{}]".format(host.split("ERROR: ")[1]))
    if domain == host:
      return color_rdata(rdata_item)
    rdata_item = color_rdata(rdata_item) + " " + color_structure("─") * (max6 - len(rdata_item) + 1) + " "
    return rdata_item + get_records(host, rbase, "", original_rdata_item)
  else:
    subs = extract_subs(rdata_item)
    if len(subs) != 0:
      all_subs = ""
      if len(subs) == 1:
        if not subs[0] == rdata_item:
          all_subs += rbase + color_structure(STEPS * " " + " └" + STEPS * "─") + " " +  get_records(subs[0], rbase + "    ")
          all_subs = color_rdata(rdata_item) + "\n" + all_subs
          return all_subs
        return get_records(subs[0], rbase, rdata_item)
      else:
        for sub in subs:
          if sub == domain:
            if sub == subs[-1]:
              all_subs += rbase + color_structure(STEPS * " " + " └" + STEPS * "─") + " " + color_domain(sub)
            else:
              all_subs += rbase + color_structure(STEPS * " " + " ├" + STEPS * "─") + " " + color_domain(sub) + "\n"
          else:
            if sub == subs[-1]:
              all_subs += rbase + color_structure(STEPS * " " + " └" + STEPS * "─") + " " + get_records(sub, rbase + STEPS * " " + " ")
            else:
              all_subs += rbase + color_structure(STEPS * " " + " ├" + STEPS * "─") + " " + get_records(sub, rbase + color_structure(STEPS * " " + " │")) + "\n"
        all_subs = color_rdata(rdata_item) + "\n" + all_subs
        return all_subs
  return color_rdata(rdata_item)

def handle_mid_record(domain,base,return_data,record,print_data,block,mid_record,end_m_item,mid_m_item):
  rdata = return_data.get(record)
  max4 = max6 = 0
  cdistance = 0
  l_rdata = []
  if record == "A": 
    max4 = get_max(rdata)
    cdistance = max4 + 3
  if record == "AAAA": 
    max6 = get_max(rdata)
    cdistance = max6 + 3
  if not (len(rdata) == 1 and rdata[0] == block):
    print_data += mid_record + color_records(record)
  for item in rdata:
    item = item
    if not item == block:
      l_rdata.append(item)
  if len(l_rdata) > 0:
    last_rdata_item = l_rdata[-1]
    for rdata_item in l_rdata:
      at_last = False
      if rdata_item == last_rdata_item: 
        cbase = base + color_structure(" " * STEPS + " │" + " " * STEPS + "  ") + cdistance * " "
        at_last = True
      else:
        cbase = base + color_structure(" " * STEPS + " │" + " " * STEPS + " │") + cdistance * " "
      rdata_item = parse_rdata(domain,rdata_item, record, max4, max6, cbase)
      if at_last:
        print_data += end_m_item + rdata_item
      else:
        print_data += mid_m_item + rdata_item
  return print_data

def handle_end_record(domain,base,return_data,record,print_data,block,end_record,end_e_item,mid_e_item,records):
  rdata = return_data.get(record)
  max4 = max6 = 0
  cdistance = 0
  l_rdata = []
  if record == "A": 
    max4 = get_max(rdata)
    cdistance = max4 + 3
  if record == "AAAA": 
    max6 = get_max(rdata)
    cdistance = max6 + 3
  if not (len(rdata) == 1 and rdata[0] == block):
    print_data += end_record + color_records(record)
  else:
    if len(records) > 1:
      print_data += "\n" + base + color_structure(" " * STEPS + " └" + "─" * STEPS) + " " + color_records(".")
  for item in rdata:
    item = item
    if not item == block:
      l_rdata.append(item)
  if len(l_rdata) > 0:
    last_rdata_item = l_rdata[-1]
    for rdata_item in l_rdata:
      at_last = False
      if rdata_item == last_rdata_item: 
        cbase = base + "        " + cdistance * " "
        at_last = True
      else:
        cbase = base + color_structure(" " * STEPS + " " + " " * STEPS + " "  + " │") + cdistance * " "
      rdata_item = parse_rdata(domain, rdata_item, record, max4, max6, cbase)
      if at_last:
        print_data += end_e_item + rdata_item
      else:
        print_data += mid_e_item + rdata_item
  return print_data

def get_records(domain, base="", first_title="", block=""):
  
  cbase = ""
  return_data = {}

  if first_title == "":
    print_data = domain
  else:
    print_data = first_title
  
  print_data = color_domain(print_data)

  mid_record = "\n" + base + color_structure(" " * STEPS + " ├" + "─" * STEPS) + " "
  end_record = "\n" + base + color_structure(" " * STEPS + " └" + "─" * STEPS) + " "
  mid_m_item = "\n" + base + color_structure(" " * STEPS + " │" + " " * STEPS + " ├" + "─" * STEPS) + " "
  end_m_item = "\n" + base + color_structure(" " * STEPS + " │" + " " * STEPS + " └" + "─" * STEPS) + " "
  mid_e_item = "\n" + base + color_structure(" " * STEPS + "  " + " " * STEPS + " ├" + "─" * STEPS) + " "
  end_e_item = "\n" + base + color_structure(" " * STEPS + "  " + " " * STEPS + " └" + "─" * STEPS) + " "

  cont = False
  if ONLY_IN_SCOPE:
    for item in IN_SCOPE_DOMAINS:
      if item in domain:
        cont = True
    if not cont:
      return print_data

  if domain in list(already_done.keys()) or "[MONO]" + domain + "[MONO]" in list(already_done.keys()) :
    return "[$$$]" + print_data + "[$$$]"
  
  if len(inspect.stack()) >= maximum_recursion_depth:
    print_data += color_structure(" [RECURSION LIMIT]")
    return print_data

  
  if len(CUSTOM_RECORD_TYPES) > 0:
    for rdtype in CUSTOM_RECORD_TYPES:
      return_data = dict(return_data, **extract_record_data(domain,rdtype))
  else:
    return_data = dict(return_data, **extract_record_data(domain,"ANY"))
  
  valid_records = list(return_data.keys())
  if len(valid_records) > 0:
    last_record = valid_records[-1]
    for record in valid_records:
      record = str(record)
      if record == last_record:
        print_data = handle_end_record(domain,base,return_data,record,print_data,block,end_record,end_e_item,mid_e_item,valid_records)
      else:
        print_data = handle_mid_record(domain,base,return_data,record,print_data,block,mid_record,end_m_item,mid_m_item)
  return print_data

def init_all(extract_subdomains_from_any_return=False
            ,query_ns_servers_for_axfr_of_own_domain=False
            ,custom_record_types=[],in_scope_domains=[]
            ,verbous=False,ids_one_by_one=[],only_in_scope=False
            ,timeout=5,steps=2):
  global name_servers,VERBOUS,EXTRACT_SUBDOMAINS_FROM_ANY_RETURN,QUERY_NS_SERVERS_FOR_AXFR_OF_OWN_DOMAIN
  global IN_SCOPE_DOMAINS,IDS_ONE_BY_ONE,ONLY_IN_SCOPE,TIMEOUT,STEPS,CUSTOM_RECORD_TYPES
 
  VERBOUS = verbous
  
  EXTRACT_SUBDOMAINS_FROM_ANY_RETURN = extract_subdomains_from_any_return
  QUERY_NS_SERVERS_FOR_AXFR_OF_OWN_DOMAIN = query_ns_servers_for_axfr_of_own_domain
  CUSTOM_RECORD_TYPES = custom_record_types
  IN_SCOPE_DOMAINS = in_scope_domains
  IDS_ONE_BY_ONE = ids_one_by_one
  ONLY_IN_SCOPE = only_in_scope
  TIMEOUT = timeout
  STEPS = steps

  os.system('cls' if os.name == 'nt' else 'clear')
  for name_server in list(name_servers.keys()):
    if test_tcp_connection(name_server,53):
      name_servers[name_server] = True
    else:
      if test_udp_connection(name_server,53):
        name_servers[name_server] = False
      else:
        name_servers[name_server] = None

def parser_error(errmsg):
    print("Usage: python3 " + sys.argv[0] + " [Options] -d <domain> use -h for help")
    print("Error: " + errmsg)
    exit()

def string_to_list(string):
  if "," in string:
    return string.split(",")
  elif string != "":
    return [string]
  else:
    return []

def main(target):
  
  data = get_records(target)
  lines = data.splitlines()
  if len(lines) < 2:
    return "",[],[]
  final_data = []
  for line in lines:
    if "[$$$]" in line:
      done_data = line.split("[$$$]")[1]
      for i in range(len(final_data)):
        if done_data in final_data[i]:
          line = line.split("[$$$]" + done_data + "[$$$]")[0] + done_data + color_domain(" [LINE {}]".format(i + 1))
          break
      if "[$$$]" in line:
        line = line.split("[$$$]" + done_data + "[$$$]")[0] + done_data
    final_data.append(line.replace("[NEW]","\n"))
  all_final = "\n".join([str(str(color_structure(str("[{}] " + "-" * (3 + (len(str(len(final_data) + 1))) - len(str(i + 1))) + ">") + " ").format(str(i + 1)) + final_data[i])) for i in range(len(final_data))])
  return all_final,"",""

if __name__ == '__main__':

  parser = argparse.ArgumentParser(epilog='\tExample: \r\npython3 ' + sys.argv[0] + " -d yahoo.com")
  parser.error = parser_error
  parser._optionals.title = "OPTIONS"
  parser.add_argument('-d', '--domain', help="Domain name to enumerate", required=True)
  parser.add_argument('-r', '--recursion_depth', help='Maximum recursion depth for the looping', type=int, default=20)
  parser.add_argument('-s', '--servers', help='NemeServers to query for dns records', type=str, default="8.8.8.8,8.8.4.4,208.67.222.222,208.67.220.220")
  parser.add_argument('-q', '--queries', help='Custom dns query types', type=str, default="")
  parser.add_argument('-o', '--only_in_scope', help='Block any subdomain that is not belonging the target domain',action='store_true')
  parser.add_argument('-i', '--in_scope_domains', help='Domains that will not be blocked at querying when -o/--only-in-scope used', type=str, default="")
  parser.add_argument('-b', '--ids_one_by_one', help='Works when no custom queries set and using it will query for every record type instead of using [ANY]',action='store_true')
  parser.add_argument('-t', '--timeout', help='Timeout for any tcp/udp connection',type=int,default=5)
  parser.add_argument('-w', '--width', help='Width between two successive columns',type=int,default=2)
  parser.add_argument('-a', '--extract_all', help='Extract subdomains from any return',action='store_true')
  parser.add_argument('-n', '--axfr_check', help='Query NS servers for axfr of the own domain',action='store_true')
  parser.add_argument('-v', '--verbous', help='Verbous querying', action='store_true')
  
  args = parser.parse_args()
  target = args.domain
  maximum_recursion_depth = args.recursion_depth
  if len(string_to_list(args.servers)) > 0:
    name_servers = {}
  for ser in string_to_list(args.servers):
    name_servers[ser] = None
  EXTRACT_SUBDOMAINS_FROM_ANY_RETURN = args.extract_all
  QUERY_NS_SERVERS_FOR_AXFR_OF_OWN_DOMAIN = args.axfr_check
  CUSTOM_RECORD_TYPES = string_to_list(args.queries)
  IN_SCOPE_DOMAINS = []
  for dom in string_to_list(args.in_scope_domains):
    IN_SCOPE_DOMAINS.append(dom)
  IDS_ONE_BY_ONE = args.ids_one_by_one
  ONLY_IN_SCOPE = args.only_in_scope
  TIMEOUT = args.timeout
  STEPS = args.width
  VERBOUS = args.verbous
  init_all(EXTRACT_SUBDOMAINS_FROM_ANY_RETURN,QUERY_NS_SERVERS_FOR_AXFR_OF_OWN_DOMAIN
          ,CUSTOM_RECORD_TYPES,IN_SCOPE_DOMAINS,VERBOUS,IDS_ONE_BY_ONE,ONLY_IN_SCOPE,TIMEOUT,STEPS)
  erase_last_line()
  ret = main(target)[0]
  os.system('cls' if os.name == 'nt' else 'clear')
  print(ret)
  
