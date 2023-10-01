# cryptoconfigparser

A simple wrapper of configparser to allow encrypt config.

## AESCryptoConfigParser

Place your `key string` as a local file mode.

Sample config

```ini
[settings]
key_file={location key file}

[Test]
site=test.site
password={your ciphertext}
```

Sample code

```python
import os
import tempfile
import shutil
from cryptoconfigparser import AEScryptoConfigParser

temp_dir = tempfile.mkdtemp()

test_key = '{your key}'

key_file = os.path.join(temp_dir, 'test.key')
with open(key_file, 'w') as file:
    file.write(test_key)

test_config =f'''
[settings]
key_file={test_key}

[Test]
site=test.site
password={your ciphertext}
'''

configFile = os.path.join(temp_dir, 'test.conf')
with open(configFile, 'w') as file:
    file.write(test_config)


config = AEScryptoConfigParser(configFile, 'utf-8')

normal_config = config.get('Test', 'site')
result = config.decrypt('Test', 'password')
print(result)

shutil.rmtree(temp_dir)
```

## SSMCryptoConfigParser

Place your `key string` as a AWS Secrets Manager's secret_string.

Sample config

```ini
[settings]
secret_name={your secret name}

[Test]
site=test.site
password={your ciphertext}
```

## KMSCryptoConfigParser

Use AWS KMS and aws-encryption-sdk to encryption.

Sample config

```ini
[settings]
key_id={your kms key id}

[Test]
site=test.site
password={your ciphertext}
```

## LICENSE

I inherited BSD 2-Clause License from [pycryptodome](https://pypi.org/project/pycryptodome/)

