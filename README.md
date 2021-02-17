## This project is no longer maintained. Feel free to fork this project and continue development of it!

# pyFireEye

Python API bindings for FireEye Products


## Installation

```bash
pip3 install pyFireEye
```
or

simply clone the repository and run 

```bash
python setup.py install
```

The only requirement is the requests library


## Usage

We currently have most of HX, AX, CMS, and FaaS endpoints implemented in some form, though some endpoints are more
complete than others. 

after installation is complete, you should be able to access the library's components as follows


```python
from pyFireEye.hx import HX
from pyFireEye.ax import AX
from pyFireEye.cms import CMS
from pyFireEye.faas import FaaS

```

As the rest of FireEye's services are added, they will be accessible in a similar way


Please review the Documentation for the FireEye API for more details about specific parameters
in routes. We hope to include all usage details within this project eventually. 

Examples on how to use various components of the bindings can be found in the [examples](examples) directory.

As an additional note, the account that you are using to authenticate needs to be configured by your FE admin to enable API access.

## Responses

To make things a bit simpler, we added simplified response classes that the different endpoints can return.
None of the responses should ever need to be instantiated directly, but are instead returned from the implemented
endpoints. 

These are 
* FEResponse
* JsonResponse
* ZipResponse
* RedlineResponse
* XMLResponse
* StreamResponse
* ErrorResponse

These can be accessed as such
```python
from pyFireEye.utilities.responses import (
    JsonResponse, 
    FEResponse, 
    ZipResponse, 
    RedlineResponse, 
    XMLResponse, 
    StreamResponse,
    ErrorResponse
    )
```

they can be used to verify the responses from the endpoints

### FEResponse/XMLResponse

The FEResponse is the basic response returned for endpoints which do not fit in the other categories. 
It is identical to XMLResponse in usage

after a request as completed which returns an FEResponse or XMLResponse

```python

# response content as a dictionary. The whole raw response
response.content

# response headers as a dictionary
response.headers

# response status code
response.status

# if there was a message
response.message

# if the response contained a data field, it will be removed from response.content 
# and placed here for easier access
response.data

# some FireEye response data contains a list of multiple results
# if this is the case, that list will be removed from response.data and stored in
response.entries

# to get the response as a dictionary
response.json()

```

### JsonResponse

The JsonResponse is the most common response returned. This means data returned from
FireEye was JSON. 

```python
# response content
response.content

# response headers as a dictionary
response.headers

# response status code
response.status

# if there was a message
response.message

# 

# to get the response as a dictionary
response.json()

```

### ZipResponse/RedlineResponse

These two response types are very similar

The content of both will contain a "zip" file stored as bytes.

The ZipResponse has a default password of unzip-me (per fireeye documentation) while
the RedlineResponse has no default password.

```python
# to unzip zip response to target directory
response.unzip(password="leave blank if default", path="path to unzip to, if none will be current working directory")

# to unzip redline response to target directory
response.unzip_file(path="path to unzip to, if none will be current working directory")

# you can also save the raw zip/mans files

# for zip response
response.zip_save(filename="filename.zip", path="")

# for redline response
response.output_raw_results(filename="filename.mans", path="")

# if filenames are not given, "random" filenames will be generated

```

### StreamResponse

The stream response contains the same status, content, and headers variables

The difference is that content will contain a dictionary. 
The data and filename entries will be filled or None, depending on if you supplied
an output file name in the calling method.

    {
        "data_length": <int>,
        "data": None if output file was provided, else byte string containing data,
        "filename": name of output file if provided, else None
    }

