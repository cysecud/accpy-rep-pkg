This repository contains the artifacts (scripts, data, and instructions) to reproduce the results discussed in our scientific paper. The package supports static and dynamic security analyses on Python packages using Bandit, GuardDog, and TShark.

Follow the steps below to set it up and validate its general functionality.


## Step 1: Configure the environment  ##

Install the required system dependencies:
```bash
sudo apt install tshark docker.io
```

Set up a Python virtual environment:
```bash
python3 -m venv ./venv
. ./venv/bin/activate
./venv/bin/python3 -m pip install -r requirements.txt
```

## Step 2: Download the package index ##

Download the list of packages from the package index (defaults to PyPI.org):
```bash
./venv/bin/python3 show_index.py > index.list
```


## Step 3: Run the analysis ##

> NOTE: Run these steps for each package in the index. For convenience here are shown for package _aenum_

Collect data using the Bandit SAST tool:
```bash
./venv/bin/python3 bandit.py aenum
```

Collect data using the GuardDog SAST tool:
```bash
sudo -E ./venv/bin/python3 guarddog.py aenum
```

Collect data using dynamic analysis of network traffic:
```bash
sudo -E ./venv/bin/python3 dynamic.py aenum
```

## Step 4: Process the data ##

Post-process collected data:
```bash
./venv/bin/python3 process.py
```

You will find the processed data in the `./results` folder.

> You find a sample of the already processed result data in this repo. You can contact us for the full data.

## Survery data

Raw data from the survey is available in `/resources/survey.csv`.  
Sensitive data is redacted and replaced with `[REDACTED]`.

## Reference

If you use our work in your research, or it helps it, or if you simply like it, please cite XXX in your publications. 
Here is an example BibTeX entry:

```
@inproceedings{XXXXX,
	title= {XXXX},
	author= {XXXX},
	booktitle= {XXXX},
	series= {XXX},
	publisher= {XXX},
	year= {2025}
}
```

## License ##
The software we developed is distributed under MIT license. See the [license](./LICENSE.md) file.
