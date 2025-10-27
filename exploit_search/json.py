import json
import os 
import subprocess
import shutil

def get_url():
  os.system
  os.system(f"curl https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json >> msf_module.json")
get_url()

msf_module = os.path.abspath('msf_module.json')
print(msf_module)

# Load your original data
with open(msf_module, 'r') as f:
    data = json.load(f)

# Transform the data
result = []
for key, value in data.items():
    result.append({
        "title": value["name"].lower(),
        "module": value["fullname"],
        "link": f"https://www.rapid7.com/db/modules/{value['fullname']}",
        "references": value.get("references", []),
        "description": value["description"]
    })
 
# Output as formatted JSON
print(json.dumps(result, indent=4))

# Write to file
with open('msf_module.json', 'w') as f:
    f.write(json.dumps(result, indent=4))
#os.chdir("files")
#os.system(f"rm msf_module.json")
#os.system(f"cd ..")
shutil.move("msf_module.json" , "files/msf_module.json")

