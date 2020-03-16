<p align="center">
  <img src="https://insidersec.io/wp-content/uploads/2020/03/insider-novo-logo.png">
</p>

Insider is the [OSS](https://opensource.org/) CLI project from the [Insider Application Security](https://insidersec.io) Security Team for the community.
This project have a simplified version of the proprietary Static Application Security Testing engine developed internally by us :smile:, to make source code analysis to find vulnerabilities right in the source code, focused on a agile and easy to implement software inside your DevOps pipeline.



## Installation
We have precompiled binaries for Linux and Windows operational systems that you can find [here](https://github.com/insidersec/insider/releases) :smile:

But if you are (g)old school or just want to compile it yourself, you'll need at least [Go version 1.13.3](https://golang.org/dl/), and [GNU Make](https://www.gnu.org/software/make/) >= 4.2.1

After downloading / checking if your version is compatible, you just have to:

* `go get github.com/insidersec/insider`
* `cd $GOPATH/src/github.com/insidersec/insider`
* `make build` or `make buildWindows`
* Have fun! :rocket:

## Usage
OBS.: The target folder should contain all the source code that should be analyzed, we plan to release support for compiled binaries for iOS, and Android' APKs :smile:

```
Usage of insider:
  -force
    	Do not overwrite over the results folder
  -no-banner
    	Skips the banner printing (Useful for CI/Docker environments)
  -no-html
    	Skips the report generation in the HTML format
  -no-json
    	Skips the report generation in the JSON format
  -target string
    	Specify where to look for files to run the specific ruleset
  -tech string
    	Specify which technology ruleset to load. (Valid values are: android, ios, csharp, javascript)
```

### Contribution

- Your contributions and suggestions are heartily ♥ welcome. [**See here the contribution guidelines.**](/.github/CONTRIBUTING.md) Please, report bugs via [**issues page.**](https://github.com/insidersec/insider/issues) See here the [**security policy.**](/.github/SECURITY.md) for report security issues. (✿ ◕‿◕) 


### License

- This work is licensed under [**LGPL-3.0.**](/LICENSE.md)
