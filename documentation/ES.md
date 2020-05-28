## Instalación

Tenemos binarios precompilados para los sistemas operativos Linux, Windows y macOS que puede encontrar [aquí.](https://github.com/insidersec/insider/releases)

Pero si usted es (g) de la vieja escuela o simplemente quiere compilarlo, necesitará al menos [Go versión 1.13.3](https://golang.org/dl/) y [GNU Make](https://www.gnu.org/software/make/)> = 4.2.1;

Después de descargar/verificar si su versión es compatible, simplemente:

* `go get github.com/insidersec/insider`
* `cd $GOPATH/src/github.com/insidersec/insider`
* `make build` o ` make buildWindows`
* Diviértete!

## Uso

NOTA: La carpeta de destino debe contener todo el código fuente que debe analizarse. Planeamos lanzar soporte para binarios compilados para iOS y Android APKs.

````
./insider --help

Usage of insider:
  -force
    	Overwrite the results directory. Insider does not overwrite the results directory by default - Optional
  -no-banner
    	Skips the banner printing (Useful for CI/Docker environments) - Optional
  -no-html
    	Skips the report generation in the HTML format - Optional
  -no-json
    	Skips the report generation in the JSON format - Optional
  -target string
    	Specify where to look for files to run the specific ruleset
        -target <folder>
        -target <myprojectfolder>
  -tech string
    	Specify which technology ruleset to load. (Valid values are: android, ios, csharp, javascript)
        -tech javascript
        -tech csharp
````

## Ejemplo

````
wget https://github.com/insidersec/insider/releases/download/1.0.0/insider-linux-amd64
chmod +x insider-linux-amd64
./insider-linux-amd64 -tech android -target example-master/
cat results/report.json
````

### Contribución

- Tus contribuciones y sugerencias son bienvenidas ♥. [Consulte las pautas de contribución aquí.](/.Github/CONTRIBUTING.md) Informe los errores a través de [página del problema.](https://github.com/insidersec/insider/issues) Consulte aquí la [política de seguridad.](/.Github/SECURITY.md) para informar problemas de seguridad. (✿ ◕‿◕)

### Licencia

- Este trabajo está licenciado bajo [LGPL-3.0.](/LICENSE.md)
