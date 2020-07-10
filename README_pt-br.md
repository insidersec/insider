<p align="center">
  <img src="https://insidersec.io/wp-content/uploads/2020/03/insider-novo-logo.png">
  <p align="center">
    <a href="https://github.com/insidersec/insider/blob/master/LICENSE.md">
      <img src="https://img.shields.io/badge/license-LGPL-blue.svg">
    </a>
    <a href="https://github.com/insidersec/insider/releases">
      <img src="https://img.shields.io/badge/version-2.0.4-blue.svg">
    </a>
  </p>
</p>

Esse documento está disponível nas versões: [`Português`](https://github.com/insidersec/insider/blob/master/README_pt-br.md) e [`Inglês`](https://github.com/insidersec/insider).

Insider é uma [Iniciativa Open Source](https://opensource.org/) executada através de uma Interface de Linha de Comandos (CLI) disponibilizada pelo time de segurança da [Insider Application Security](https://insidersec.io) para a comunidade.

Esse projeto possui uma versão simples do Sistema de Testes para Aplicações Estáticas (Static Application Security Testing) desenvolvido internamente por nós. Essa versão do Insider têm como objetivos: garantir os padrões de segurança estabelecidos pela [Open Web Application Security Project&reg;](https://owasp.org/), cobrir os 10 principais riscos de segurança para aplicações web - [OWASP Top 10](https://owasp.org/www-project-top-ten/), analisar e encontrar vulnerabilidades no código-fonte, focando na facilidade da implementação junto ao pipeline de DevOps e em software ágil.

Atualmente oferecemos suporte às seguintes tecnologias: Java (Maven ou Android), Kotlin (Android), Swift (iOS), .NET Full Framework, C# e Javascript (Node.js).

---

### Instalação

Disponibilizamos os arquivos binários pré-compilados para os seguintes sistemas operacionais: Linux, Windows e macOS, que você pode encontrá-los [aqui](https://github.com/insidersec/insider/releases).

Mas se você for um desenvolvedor <s>raíz</s> old school, ou simplismente deseja compilá-los, precisará de pelo menos da versão do [Go 1.13.3](https://golang.org/dl/) e uma versão maior ou igual a 4.2.1 do [GNU Make](https://www.gnu.org/software/make/).

Depois de baixar e chegar a compatibilidade das versões, você deve executar:

```bash
$ go get github.com/insidersec/insider
$ cd $GOPATH/src/github.com/insidersec/insider
$ make linux64 # Damos suporte para: linux32, linux64, win32, win64, macos
```

Pronto, divirta-se! :rocket:

---

### Utilização

OBS.:
Você deve colocar o Insider fora da pasta que contém os arquivos que serão analisados.

A pasta de destino deve conter todo o código-fonte que deve ser analisado. Planejamos liberar o suporte para binários compilados para iOS e APKs do Android futuramente.

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
# Verificar a versão correta para o seu ambiente.

$ wget https://github.com/insidersec/insider/releases/download/2.0.0/insider-linux-amd64
$ chmod +x insider-linux-amd64
$ ./insider-linux-amd64 --tech javascript  --target <projectfolder>
```

---

### Contribuição

- Suas contribuições e sugestões são muito bem-vindas ♥. [Veja aqui as diretrizes de contribuição.](/.github/CONTRIBUTING.md) Por favor, reporte os bugs na [página de bugs.](https://github.com/insidersec/insider/issues). Veja aqui a [política de segurança](/.github/SECURITY.md) para relatar problemas de segurança. (✿ ◕‿◕)

---

### Licença

- Esse projeto está sob a licença [LGPL-3.0.](/LICENSE.md)
