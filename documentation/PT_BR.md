## Instalação

Temos binários pré-compilados para sistemas operacionais Linux, Windows e macOS que você pode encontrar [aqui.](https://github.com/insidersec/insider/releases)

Mas se você é (g) old school ou apenas deseja compilá-lo, precisará de pelo menos [Go versão 1.13.3](https://golang.org/dl/) e [GNU Make](https://www.gnu.org/software/make/)> = 4.2.1;

Após fazer o download / verificar se sua versão é compatível, basta:

* `go get github.com/insidersec/insider`
* `cd $GOPATH/src/github.com/insidersec/insider`
* `make build` ou `make buildWindows`
* Diverta-se!

## Uso

OBS .: A pasta de destino deve conter todo o código-fonte que deve ser analisado. Planejamos liberar suporte para binários compilados para iOS e APKs do Android.

````
./insider -help

Usage of insider:
  -force
    	Overwrite the results directory. Insider does not overwrite the results directory by default
  -no-banner
    	Skips the banner printing (Useful for CI/Docker environments)
  -no-html
    	Skips the report generation in the HTML format
  -no-json
    	Skips the report generation in the JSON format
  -target string
    	Specify the target directory containing the Source Code
  -tech string
    	Specify which technology ruleset to load. (Valid values are: android, ios, csharp, javascript)
````

## Exemplo

```
wget https://github.com/insidersec/insider/releases/download/1.0.0/insider-linux-amd64
chmod +x insider-linux-amd64
./insider-linux-amd64 -tech android -target example-master/
cat results/report.json
```

### Contribuição

- Suas contribuições e sugestões são muito bem-vindas ♥. [Veja aqui as diretrizes de contribuição.](/.Github/CONTRIBUTING.md) Por favor, relate erros através de [página de problemas.](https://github.com/insidersec/insider/issues) Veja aqui a [política de segurança.](/.Github/SECURITY.md) para relatar problemas de segurança. (✿ ◕‿◕)


### Licença

- Este trabalho está licenciado sob [LGPL-3.0.](/LICENSE.md)
