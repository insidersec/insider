<p align="center">
  <img src="https://www.insidersec.io/wp-content/uploads/2020/11/cover-linkedin2.png">
  <p align="center">
    <a href="https://github.com/insidersec/insider/blob/master/LICENSE">
      <img src="https://img.shields.io/badge/license-MIT-green.svg">
    </a>
    <a href="https://github.com/insidersec/insider/releases">
      <img src="https://img.shields.io/github/v/release/insidersec/insider">
    </a>
  </p>
</p>

Este documento também está disponível em [`Inglês`](https://github.com/insidersec/insider).

Insider é uma [Iniciativa Open Source](https://opensource.org/) executada através de uma Interface de Linha de Comandos (CLI) disponibilizada pelo time de segurança da [Insider Application Security](https://insidersec.io) para a comunidade.

O Insider têm como objetivos: garantir os padrões de segurança estabelecidos pela [Open Web Application Security Project&reg;](https://owasp.org/), cobrir os 10 principais riscos de segurança para aplicações web - [OWASP Top 10](https://owasp.org/www-project-top-ten/), analisar e encontrar vulnerabilidades no código-fonte, focando na facilidade da implementação junto ao pipeline de DevOps e em software ágil.

Atualmente oferecemos suporte às seguintes tecnologias: Java (Maven ou Android), Kotlin (Android), Swift (iOS), .NET Full Framework, C# e Javascript (Node.js).

Existe um Github Action que permite proteger seu repositório com Insider, gratuito, fácil de integrar e sem atrito. É a maneira mais fácil de proteger seu código diretamente em seu repositório. [Insider-Action](https://github.com/insidersec/insider-action)

---

### Instalação

Você pode instalar o Insider usando binários pré-compilados ou da fonte.

#### Binários pré-compilados

Temos binários pré-compilados para os sistemas operacionais Linux, Windows e macOS que você pode encontrar [aqui.] (Https://github.com/insidersec/insider/releases)

Pronto, divirta-se! :rocket:

---

### Utilização

```
insider is the CLI project from the Insider Application Security Team for the community

Usage:
  -exclude value
        Patterns to exclude directory or files to analyze. Can be used multiple times
  -force
        Overwrite the report file name. Insider does not overwrite the results directory by default (default false)
  -jobs int
        Number of analysis to execute in parallel (default 4)
  -no-dra
        Disable DRA analysis
  -no-html
        Skips the report generation in the HTML format
  -no-json
        Skips the report generation in the JSON format
  -quiet
        No output logs of execution
  -security float
        Set the Security level, values between 0 and 100 (default 0)
  -target string
        Specify where to look for files to run the specific ruleset
  -tech string
        Specify which technology ruleset to load
  -v    Enable verbose output
  -version
        Show version and quit with exit code 0

Supported technologies:
        android
        java
        ios
        javascript
        csharp

Example of use:
        # Run JavaScript analysis on specific directoty
        insider -tech javascript -target <directory>

        # Run Android analysis on specific directoty and ignore html and json report
        insider -tech android -target <directory> -no-html -no-json

        # Run Java analysis on specific directoty with a base security value to fail
        insider -tech java -target <directory> -security 20

        # Run JavaScript analysis on specific directoty and exclude node_modules and test files
        insider -tech javascript -target <directory> -exclude tests/* -exclude node_modules/*
```

---

### Exemplo

```bash
# Check the correct release for your environment
$ wget https://github.com/insidersec/insider/releases/download/2.1.0/insider_2.1.0_linux_x86_64.tar.gz
$ tar -xf insider_2.1.0_linux_x86_64.tar.gz 
$ chmod +x insider
$ ./insider --tech javascript  --target <projectfolder>
```
---

---

### Docker

Você também pode utilizar o `insider` dentro de um container. Você só precisar montar um volume com o diretorio que deseja realizar a analise:

```bash
$ docker run --rm -v $(pwd):/target-project insidersec/insider -tech <tech> -target /target-project

```

---


### Demo

![Gif](demo.gif)

---

### Contribuição

- Suas contribuições e sugestões são muito bem-vindas ♥. [Veja aqui as diretrizes de contribuição.](/.github/CONTRIBUTING.md) Por favor, reporte os bugs na [página de bugs.](https://github.com/insidersec/insider/issues). Veja aqui a [política de segurança](/.github/SECURITY.md) para relatar problemas de segurança. (✿ ◕‿◕)

---
#### Compilando manualmente

Para compilar o Insider manualmente você vai precisar do [Go version 1.13](https://golang.org/dl/).

```bash
$ go get github.com/insidersec/insider/cmd/insider
```
---
### Licença

- Esse projeto está sob a licença [MIT](/LICENSE).
