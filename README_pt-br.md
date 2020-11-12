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

OBS .:
Não coloque o insider na mesma pasta que contém os arquivos a serem analisados.

A pasta de destino deve conter todo o código-fonte que deve ser analisado, planejamos lançar suporte para binários compilados para iOS e APKs do Android.

```
./insider --help
Insider é o projeto CLI do time de segurança da Insider Application Security para a comunidade

Comandos:
  -force
        Substitua o nome do arquivo de relatório. O Insider não substitui o diretório de resultados por padrão. - Opcional

  -no-banner
        Ignore a impressão do banner (Útil para ambientes CI / Docker). - Opcional

  -no-html
        Ignore a criação do relatório no formato HTML. - Opcional

  -no-json
        Ignore a criação do relatório no formato JSON. - Opcional

  -security int
        Configure o nível de segurança. Insira um valor entre 0 e 100.

  -target string
        Especifique onde procurar os arquivos e executar um conjunto de regras específico.
            -target <folder>
            -target <myprojectfolder>

  -tech string
        Especifique qual conjunto de regras de tecnologia deve ser carregado. Os valores válidos são: android, ios, csharp e javascript.
            -tech javascript
            -tech csharp

  -v    Defina uma saída detalhada (verbosa).

Exemplos de uso:
        insider -tech javascript -target <myprojectfolder>
        insider -tech=android -target=<myandroidfolder>
        insider -tech android -target <myfolder> -no-html
```

---

### Exemplo

```bash
# Check the correct release for your environment
$ mkdir insider && cd insider
$ wget https://github.com/insidersec/insider/releases/download/2.0.5/insider_2.0.5_linux_x86_64.tar.gz
$ tar -xf insider_2.0.5_linux_x86_64.tar.gz 
$ chmod +x insider
$ ./insider --tech javascript  --target <projectfolder>
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
$ go get github.com/insidersec/insider
```
---
### Licença

- Esse projeto está sob a licença [MIT](/LICENSE).
