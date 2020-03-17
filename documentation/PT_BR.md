## Instalação
Temos binários pré-compilados para sistemas operacionais Linux e Windows que você pode encontrar [aqui](https://github.com/insidersec/insider/releases) :smile:

Mas se você é (g) old school ou apenas deseja compilá-lo, precisará de pelo menos [Go versão 1.13.3](https://golang.org/dl/) e [GNU Make](https://www.gnu.org/software/make/)> = 4.2.1

Após fazer o download / verificar se sua versão é compatível, basta:

* `go get github.com/insidersec/insider`
* `cd $GOPATH/src/github.com/insidersec/insider`
* `make build` ou `make buildWindows`
* Diverta-se! :foguete:

## Uso
OBS .: A pasta de destino deve conter todo o código-fonte que deve ser analisado. Planejamos liberar suporte para binários compilados para iOS e APKs do Android: smile:

````
Uso de insider:
  -force
    Não substitua sobre a pasta de resultados
  -no-banner
    Ignora a impressão do banner (Útil para ambientes de CI/Docker)
  -no-html
    Ignora a geração do relatório no formato HTML
  -no-json
    Ignora a geração de relatório no formato JSON
  -target string
    Especifique onde procurar arquivos para executar o conjunto de regras específico
  -tech string
    Especifique qual conjunto de regras de tecnologia carregar. (Os valores válidos são: android, ios, csharp, javascript)
````

### Contribuição

- Suas contribuições e sugestões são muito bem-vindas ♥. [**Veja aqui as diretrizes de contribuição.**](/.Github/CONTRIBUTING.md) Por favor, relate erros através de [**página de problemas.**](https://github.com/insidersec/insider/issues) Veja aqui a [**política de segurança.**](/.Github/SECURITY.md) para relatar problemas de segurança. (✿ ◕‿◕)


### Licença

- Este trabalho está licenciado sob [**LGPL-3.0.**](/LICENSE.md)