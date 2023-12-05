# Python CICFlowMeter

> This project is cloned from [Python Wrapper CICflowmeter](https://gitlab.com/hieulw/cicflowmeter) and customized to fit my need. Therefore, it is not maintained actively. If there are any problems, please create an issue or a pull request.  


### Installation
```sh
git clone https://github.com/whit3vill/cicflowmeter.git
cd cicflowmeter
python3 setup.py install
```

### Usage
```sh
usage: cicflowmeter [-h] (-f INPUT_FILE) [-c] [-u URL_MODEL] output

positional arguments:
  output                output file name (in flow mode) or directory (in sequence mode)

optional arguments:
  -h, --help            show this help message and exit
  -f INPUT_FILE         capture offline data from INPUT_FILE
  -c, --csv, --flow     output flows as csv
```

Convert pcap file to flow csv:

```
cicflowmeter -f example.pcap -c flows.csv
```

- Reference: https://www.unb.ca/cic/research/applications.html#CICFlowMeter

# cicids csv to Elastic
python3 elastic.py -i [index] -f [filename.csv] -e [elastic_host_address] -a [elastic_api_key]
