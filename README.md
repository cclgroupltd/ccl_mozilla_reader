# ccl_mozilla_reader
Package for reading data from Mozilla Firefox data sources.

## MozillaProfileFolder
The `MozillaProfileFolder` class is intended to act as a convenient entry-point to
much of the useful functionality in the package. It performs on-demand loading of 
data, so the "start-up cost" of using this object over the individual modules 
is near-zero, but with the advantage of better searching and filtering 
functionality built in and an easier interface to bring together data from these
different sources.

## TODO
Much documentation.