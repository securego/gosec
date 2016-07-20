## GAS - Go AST Scanner

Inspects source code for security problems by scanning the Go AST.

### Usage

Gas can be configured to only run a subset of rules, to exclude certain file
paths, and produce reports in different formats. By default all rules will be
run against the supplied input files. To recursively scan from the current
directory you can supply './...' as the input argument.

#### Selecting rules

By default Gas will run all rules against the supplied file paths. It is however possible to select a subset of rules to run via the '-rule=' flag.

##### Available rules

- __crypto__ - Detects use of weak cryptography primatives
- __tls__ - Detects if TLS certificate verification is disabled
- __sql__ - SQL injection vectors
- __hardcoded__ - Potential hardcoded credentials
- __perms__ - Insecure file permissions
- __tempfile__ - Insecure creation of temporary files
- __unsafe__- Detects use of the unsafe pointer functions
- __bind__- Listening on all network interfaces
- __rsa__- Weak RSA keys


```
$ gas -rule=rsa -rule=tls -rule=crypto ./...
```

#### Excluding files:

Gas will ignore paths that match a supplied pattern via
[filepath.Match](https://golang.org/pkg/path/filepath/#Match).
Multiple patterns can be specified as follows:

```
$ gas -exclude tests* -exclude *_example.go ./...
```

#### Annotating code

In cases where Gas reports a failure that has been verified as being safe.
In these cases it is possible to annotate the code with a '#nosec' comment.
The annotation causes Gas to stop processing any further nodes within the
AST so can apply to a whole block or more granularly to a single expression.

```go

import "md5" // #nosec


func main(){

    /* # nosec */
    if x > y {
        h := md5.New() // this will also be ignored
    }

}

```

In some cases you may also want to revisit places where #nosec annotations
have been used. To run the scanner and ignore any #nosec annotations you can
 do the following:

```
$ gas -nosec=true ./...
```

### Output formats

Gas currently supports text, json and csv output formats. By default results
will be reported to stdout, but can also be written to an output file. The
output format is controlled by the '-fmt' flag, and the output file is
controlled by the '-out' flag as follows:

```
# Write output in json format to results.json
$ gas -fmt=json -out=results.json *.go
```
