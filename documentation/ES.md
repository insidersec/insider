## Instalación

Tenemos binarios precompilados para los sistemas operativos Linux y Windows que puede encontrar [aquí.](https://github.com/insidersec/insider/releases)

Pero si usted es (g) de la vieja escuela o simplemente quiere compilarlo, necesitará al menos [Go versión 1.13.3](https://golang.org/dl/) y [GNU Make](https://www.gnu.org/software/make/)> = 4.2.1;

Después de descargar/verificar si su versión es compatible, simplemente:

* `go get github.com/insidersec/insider`
* `cd $GOPATH/src/github.com/insidersec/insider`
* `make build` o ` make buildWindows`
* Diviértete!

## Uso

NOTA: La carpeta de destino debe contener todo el código fuente que debe analizarse. Planeamos lanzar soporte para binarios compilados para iOS y Android APKs.

````
Uso de información privilegiada:
  -force
    No sobrescriba la carpeta de resultados
  -no-banner
    Ignora la impresión de pancartas (útil para entornos CI / Docker)
  -no-html
    Ignora la generación de informes en formato HTML
  -no-json
    Ignora la generación de informes en formato JSON
  -target
    Especifique dónde buscar archivos para ejecutar el conjunto de reglas específico
  -tech
    Especifique qué conjunto de reglas tecnológicas cargar. (Los valores válidos son: android, ios, csharp, javascript)
````

### Contribución

- Tus contribuciones y sugerencias son bienvenidas ♥. [Consulte las pautas de contribución aquí.](/.Github/CONTRIBUTING.md) Informe los errores a través de [página del problema.](https://github.com/insidersec/insider/issues) Consulte aquí la [política de seguridad.](/.Github/SECURITY.md) para informar problemas de seguridad. (✿ ◕‿◕)

### Licencia

- Este trabajo está licenciado bajo [LGPL-3.0.](/LICENSE.md)