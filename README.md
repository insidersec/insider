<p align="center">
  <img src="https://insidersec.io/wp-content/uploads/2020/03/insider-novo-logo.png">
  <p align="center">
    <a href="https://github.com/insidersec/insider/blob/master/LICENSE.md">
      <img src="https://img.shields.io/badge/license-LGPL-blue.svg">
    </a>
    <a href="https://github.com/insidersec/insider/releases">
      <img src="https://img.shields.io/badge/version-1.0.1-blue.svg">
    </a>
  </p>
</p>

Insider is the [OSS](https://opensource.org/) CLI project from the [Insider Application Security](https://insidersec.io) Security Team for the community.
This project have a simplified version of the proprietary Static Application Security Testing engine developed internally by us, this version of Insider is exclusively focused on covering the [OWASP Top 10](https://owasp.org/www-project-top-ten/), to make source code analysis to find vulnerabilities right in the source code, focused on a agile and easy to implement software inside your DevOps pipeline.

## Installation

We have precompiled binaries for Linux, Windows and macOS operational systems that you can find [here](https://github.com/insidersec/insider/releases)

But if you are (g)old school or just want to compile it yourself, you'll need at least [Go version 1.13.3.](https://golang.org/dl/), and [GNU Make](https://www.gnu.org/software/make/) >= 4.2.1;

After downloading / checking if your version is compatible, you just have to:

* `go get github.com/insidersec/insider`
* `cd $GOPATH/src/github.com/insidersec/insider`
* `make linux64` or `make win64` or `make macos` or `make all`

We support:
* `linux32`
* `linux64`
* `win32`
* `win64`
* `macos`

Have fun! :rocket:

## Usage

OBS.: The target folder should contain all the source code that should be analyzed, we plan to release support for compiled binaries for iOS, and Android' APKs.

````
./insider --help

Insider is the CLI project from the Insider Application Security Team for the community
Usage :
  -force
        Overwrite the results directory. Insider does not overwrite the results directory by default - Optional
  -no-banner
        Skips the banner printing (Useful for CI/Docker environments) - Optional
  -no-html
        Skips the report generation in the HTML format - Optional
  -no-json
        Skips the report generation in the JSON format - Optional
  -security int
        Set the Security level, values ​​between 0 and 100
  -target string
        Specify where to look for files to run the specific ruleset.
        -target <folder>
        -target <myprojectfolder>
  -tech string
        Specify which technology ruleset to load. (Valid values are: android, ios, csharp, javascript)
        -tech javascript
        -tech csharp
  -v    Set true for verbose output
Example of use :
        insider -tech javascript -target myprojectfolder 
        insider -tech=android -target=myandroidfolder 
        insider -tech android -target <myfolder>  no-html

````

## Example

````
#Check the correct release for your environment
wget https://github.com/insidersec/insider/releases/download/2.0.0/insider-linux-amd64
chmod +x insider-linux-amd64
./insider-linux-amd64 -tech=javascript  -target=<projectfolder>

````

### Contribution

- Your contributions and suggestions are heartily ♥ welcome. [See here the contribution guidelines.](/.github/CONTRIBUTING.md) Please, report bugs via [issues page.](https://github.com/insidersec/insider/issues) See here the [security policy.](/.github/SECURITY.md) for report security issues. (✿ ◕‿◕)


### License

- This work is licensed under [LGPL-3.0.](/LICENSE.md)
