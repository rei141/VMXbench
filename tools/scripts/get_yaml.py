import yaml
import sys

with open(sys.argv[1]) as f:
    config = yaml.safe_load(f)
print(config[sys.argv[2]][sys.argv[3]])