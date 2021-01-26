package report

import (
	"io"
	"net/http"
	"os"
)

const (
	CssFile = "style.css"
	CssURL  = "https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css"
)

func defaultTemplate() string {
	return `
	<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1, shrink-to-fit=no'>
    <title>Report</title>
    <link href='./style.css' rel='stylesheet' >
    <link href='https://fonts.googleapis.com/css2?family=Inconsolata:wght@300&display=swap' rel='stylesheet'>
</head>
<style>
    body {
        font-family: 'Inconsolata', monospace;
        font-size: 13px;
    }
</style>
<body>
<div class='container' style='border: rgba(0,0,0,.1) 1px solid'>
    <div class='row'>
        <div class='col-4'><img src='https://insidersec.io/wp-content/uploads/2020/03/insider-novo-logo.png' alt=''
                                class='img-fluid' style='margin-bottom: 20px'></div>
    </div>
	<div class='row'>
        <div class='col-12'>
            <h6>Score Security {{ .SecurityScore }}/100 </h6>
	</div>
	<hr>


</div>
	<hr>
	<div class='row'>
		<div class='col-12'>
					 <h7>Resume of Vulnerabilities</h7>
					<table>
						<tr><td>None</td><td>&nbsp; {{ .None }}</td></tr>
						<tr><td>Low</td><td>&nbsp; {{ .Low }}</td></tr>
						<tr><td>Medium</td><td>&nbsp; {{ .Medium }}</td></tr>
						<tr><td>High</td><td>&nbsp; {{ .High }}</td></tr>
						<tr><td>Critical</td><td>&nbsp; {{ .Critical }}</td></tr>
						<tr><td>Total</td><td>&nbsp; {{ .Total }}</td></tr>
					</table>
		</div>
	</div>
	<hr>
	<div class='row'>
		<div class='col-12'>
				You are using the Insider open source version. If you like the product and want more features, visit <a href='http://insidersec.io'>http://insidersec.io</a> and get to know our enterprise version.<br><br>

If you are a developer, then you can contribute to the improvement of the software while using an open source version
		</div>
	</div>
	<hr>
    <div class='row'>
    </div>
    {{ if .Libraries }}
        <div class='row'>
            <div class='col-12'>
                <h6>Libraries</h6>
                <div class='table-responsive'>
                    <table class='table table-sm'>
                        <thead>
                        <tr>
                            <td>Name</td>
                            <td>Version</td>
                        </tr>
                        </thead>
                        <tbody>
                        {{ range .Libraries}}
                            <tr class='user-select-all' >
                                <td>{{ .Name}}</td>
                                <td>{{ .Version}}</td>
                            </tr>
                        {{end}}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    {{end}}

    {{ if .LibraryIssues }}
    <div class='row'>
        <div class='col-12'>
            <h6>Library Issues</h6>
            <div class=''>
                <table class='table table-sm' style='table-layout:fixed;'>
                    <tbody>

                    {{ range .LibraryIssues}}
                        <tr>
                            <td class='user-select-all'><p class='text-break'>
                                    <b>Title: </b>{{ .Title }}<br>
                                    <b>CWE: </b>{{ .CWE }}<br>
                                    <b>CVE: </b>{{ .CVEs }}<br>
                                    <b>Description: </b>{{ .Description }}<br>
                                    <b>Recomendation: </b>{{ .Recomendation }}<br>
                                </p>
                            </td>
                        </tr>
                    {{end}}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    {{end}}

    {{ if .Vulnerabilities }}
    <div class='row'>
        <div class='col-12'>
            <h6>Vulnerabilities</h6>
            <div class=''>
                <table class='table table-sm' style='table-layout:fixed;'>
                    <tbody>

                    {{ range .Vulnerabilities}}
                        <tr>
                            <td class='user-select-all'><p class='text-break'>
                                    <b>CVSS: </b>{{ .CVSS }}<br>
									<b>Severity: </b>{{ .Severity}}<br>
                                    <b>Class: </b>{{ .Class}}<br>
                                    <b>VulnerabilityID :</b>{{ .VulnerabilityID}}<br>
                                    <b>Method: </b>{{ .Method}}<br>
                                    <b>Description: </b>{{ .Description}}<br>
                                    <b>ClassMessage: </b>{{ .ClassMessage}}<br>
                                    <b>Recomendation: </b>{{ .Recomendation}}<br>
                                </p>
                            </td>
                        </tr>
                    {{end}}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    {{end}}
        <div class="row" style="border-top: #dee2e6 1px solid;padding-top: 10px;">
        <div class="col-12">
            <p>Copyright 2020 insidersec.io</p>

            <p>Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:</p>

            <p>The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.</p>

            <p>THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.</p>
        </div>
    </div>
</div>

</body>
</html>`
}

func iosTemplate() string {
	return `
	<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1, shrink-to-fit=no'>
    <title>Report</title>
    <link href='./style.css' rel='stylesheet' >
    <link href='https://fonts.googleapis.com/css2?family=Inconsolata:wght@300&display=swap' rel='stylesheet'>
</head>
<style>
    body {
        font-family: 'Inconsolata', monospace;
        font-size: 13px;
    }
</style>
<body>
<div class='container' style='border: rgba(0,0,0,.1) 1px solid'>
    <div class='row'>
        <div class='col-4'><img src='https://insidersec.io/wp-content/uploads/2020/03/insider-novo-logo.png' alt=''
                                class='img-fluid' style='margin-bottom: 20px'></div>
    </div>
	<div class='row'>
		<div class='col-12'>
			<table>
				<tr><td>App name</td><td>&nbsp; {{ .IOSInfo.AppName }}</td></tr>
			</table>
		</div>
	</div>
	<hr>
	<div class='row'>
        <div class='col-12'>
            <h6>Score Security {{ .SecurityScore }}/100 </h6>
	</div>
	<hr>


</div>
	<hr>
	<div class='row'>
		<div class='col-12'>
			<h7>Resume of Vulnerabilities</h7>
			<table>
				<tr><td>None</td><td>&nbsp; {{ .None }}</td></tr>
				<tr><td>Low</td><td>&nbsp; {{ .Low }}</td></tr>
				<tr><td>Medium</td><td>&nbsp; {{ .Medium }}</td></tr>
				<tr><td>High</td><td>&nbsp; {{ .High }}</td></tr>
				<tr><td>Critical</td><td>&nbsp; {{ .Critical }}</td></tr>
				<tr><td>Total</td><td>&nbsp; {{ .Total }}</td></tr>
			</table>
		</div>
	</div>
	<hr>
	<div class='row'>
		<div class='col-12'>
				You are using the Insider open source version. If you like the product and want more features, visit <a href='http://insidersec.io'>http://insidersec.io</a> and get to know our enterprise version.<br><br>

If you are a developer, then you can contribute to the improvement of the software while using an open source version
		</div>
	</div>
	<hr>
    <div class='row'>
    </div>
    {{ if .Libraries }}
        <div class='row'>
            <div class='col-12'>
                <h6>Libraries</h6>
                <div class='table-responsive'>
                    <table class='table table-sm'>
                        <thead>
                        <tr>
                            <td>Name</td>
                            <td>Version</td>
                        </tr>
                        </thead>
                        <tbody>
                        {{ range .Libraries}}
                            <tr class='user-select-all' >
                                <td>{{ .Name}}</td>
                                <td>{{ .Version}}</td>
                            </tr>
                        {{end}}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    {{end}}

    {{ if .Permissions }}
    <div class='row'>
        <div class='col-12'>
            <h6>Permissions</h6>
            <div class=''>
                <table class='table table-sm' style='table-layout:fixed;'>
                    <tbody>

                    {{ range .Permissions}}
                        <tr>
                            <td class='user-select-all'><p class='text-break'>
                                    <b>Name: </b>{{ .Name }}<br>
                                    <b>Reason: </b>{{ .Reasone }}<br>
                                    <b>Description: </b>{{ .Description }}<br>
                                </p>
                            </td>
                        </tr>
                    {{end}}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    {{end}}

    {{ if .Vulnerabilities }}
    <div class='row'>
        <div class='col-12'>
            <h6>Vulnerabilities</h6>
            <div class=''>
                <table class='table table-sm' style='table-layout:fixed;'>
                    <tbody>

                    {{ range .Vulnerabilities}}
                        <tr>
                            <td class='user-select-all'><p class='text-break'>
                                    <b>CVSS: </b>{{ .CVSS }}<br>
									<b>Severity: </b>{{ .Severity}}<br>
                                    <b>Class: </b>{{ .Class}}<br>
                                    <b>VulnerabilityID :</b>{{ .VulnerabilityID}}<br>
                                    <b>Method: </b>{{ .Method}}<br>
                                    <b>Description: </b>{{ .Description}}<br>
                                    <b>ClassMessage: </b>{{ .ClassMessage}}<br>
                                    <b>Recomendation: </b>{{ .Recomendation}}<br>
                                </p>
                            </td>
                        </tr>
                    {{end}}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    {{end}}

        <div class="row" style="border-top: #dee2e6 1px solid;padding-top: 10px;">
        <div class="col-12">
            <p>Copyright 2020 insidersec.io</p>

            <p>Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:</p>

            <p>The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.</p>

            <p>THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.</p>
        </div>
    </div>
</div>

</body>
</html>`
}

func androidTemplate() string {
	return `
	<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1, shrink-to-fit=no'>
    <title>Report</title>
    <link href='./style.css' rel='stylesheet' >
    <link href='https://fonts.googleapis.com/css2?family=Inconsolata:wght@300&display=swap' rel='stylesheet'>
</head>
<style>
    body {
        font-family: 'Inconsolata', monospace;
        font-size: 13px;
    }
</style>
<body>
<div class='container' style='border: rgba(0,0,0,.1) 1px solid'>
    <div class='row'>
        <div class='col-4'><img src='https://insidersec.io/wp-content/uploads/2020/03/insider-novo-logo.png' alt=''
                                class='img-fluid' style='margin-bottom: 20px'></div>
    </div>
	<div class='row'>
        <div class='col-12'>
            <h6>Score Security {{ .SecurityScore }}/100 </h6>
	</div>
	<hr>


</div>
	<hr>
	<div class='row'>
		<div class='col-12'>
					 <h7>Resume of Vulnerabilities</h7>
					<table>
						<tr><td>None</td><td>&nbsp; {{ .None }}</td></tr>
						<tr><td>Low</td><td>&nbsp; {{ .Low }}</td></tr>
						<tr><td>Medium</td><td>&nbsp; {{ .Medium }}</td></tr>
						<tr><td>High</td><td>&nbsp; {{ .High }}</td></tr>
						<tr><td>Critical</td><td>&nbsp; {{ .Critical }}</td></tr>
						<tr><td>Total</td><td>&nbsp; {{ .Total }}</td></tr>
					</table>
		</div>
	</div>
	<hr>
	<div class='row'>
		<div class='col-12'>
				You are using the Insider open source version. If you like the product and want more features, visit <a href='http://insidersec.io'>http://insidersec.io</a> and get to know our enterprise version.<br><br>

If you are a developer, then you can contribute to the improvement of the software while using an open source version
		</div>
	</div>
	<hr>
    <div class='row'>
    </div>
    {{ if .Libraries }}
        <div class='row'>
            <div class='col-12'>
                <h6>Libraries</h6>
                <div class='table-responsive'>
                    <table class='table table-sm'>
                        <thead>
                        <tr>
                            <td>Name</td>
                            <td>Version</td>
                        </tr>
                        </thead>
                        <tbody>
                        {{ range .Libraries}}
                            <tr class='user-select-all' >
                                <td>{{ .Name}}</td>
                                <td>{{ .Version}}</td>
                            </tr>
                        {{end}}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    {{end}}

    {{ if .ManifestVulnerabilities }}
    <div class='row'>
        <div class='col-12'>
            <h6>Manifest Entries</h6>
            <div class=''>
                <table class='table table-sm' style='table-layout:fixed;'>
                    <tbody>

                    {{ range .ManifestVulnerabilities}}
                        <tr>
                            <td class='user-select-all'><p class='text-break'>
                                    <b>Title: </b>{{ .Title }}<br>
                                    <b>Status: </b>{{ .Status }}<br>
                                    <b>Class: </b>{{ .Class }}<br>
                                    <b>Description: </b>{{ .Description }}<br>
                                </p>
                            </td>
                        </tr>
                    {{end}}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    {{end}}

    {{ if .ManifestPermissions }}
    <div class='row'>
        <div class='col-12'>
            <h6>Manifest Permissions</h6>
            <div class=''>
                <table class='table table-sm' style='table-layout:fixed;'>
                    <tbody>

                    {{ range .ManifestPermissions}}
                        <tr>
                            <td class='user-select-all'><p class='text-break'>
                                    <b>Title: </b>{{ .Title }}<br>
                                    <b>Status: </b>{{ .Status }}<br>
                                    <b>Description: </b>{{ .Description }}<br>
                                    <b>Info: </b>{{ .Info }}<br>
                                </p>
                            </td>
                        </tr>
                    {{end}}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    {{end}}

    {{ if .Services }}
    <div class='row'>
        <div class='col-12'>
            <h6>Services </h6>
            <div class=''>
				<ul>
                    {{ range .Services}}
						<li class='user-select-all'><p class='text-break'>
							{{ .Name }}
						</li>
                    {{end}}
				</ul>
            </div>
        </div>
    </div>
    {{end}}

    {{ if .BroadcastReceivers }}
    <div class='row'>
        <div class='col-12'>
            <h6>Broadcast Receivers </h6>
            <div class=''>
				<ul>
                    {{ range .BroadcastReceivers}}
						<li class='user-select-all'><p class='text-break'>
							{{ .Name }}
						</li>
                    {{end}}
				</ul>
            </div>
        </div>
    </div>
    {{end}}

    {{ if .AvailableActivities }}
    <div class='row'>
        <div class='col-12'>
            <h6>Activities </h6>
            <div class=''>
				<ul>
                    {{ range .AvailableActivities}}
						<li class='user-select-all'><p class='text-break'>
							{{ .Name }}
						</li>
                    {{end}}
				</ul>
            </div>
        </div>
    </div>
    {{end}}

    {{ if .Vulnerabilities }}
    <div class='row'>
        <div class='col-12'>
            <h6>Vulnerabilities</h6>
            <div class=''>
                <table class='table table-sm' style='table-layout:fixed;'>
                    <tbody>

                    {{ range .Vulnerabilities}}
                        <tr>
                            <td class='user-select-all'><p class='text-break'>
                                    <b>CVSS: </b>{{ .CVSS }}<br>
									<b>Severity: </b>{{ .Severity}}<br>
                                    <b>Class: </b>{{ .Class}}<br>
                                    <b>VulnerabilityID :</b>{{ .VulnerabilityID}}<br>
                                    <b>Method: </b>{{ .Method}}<br>
                                    <b>Description: </b>{{ .Description}}<br>
                                    <b>ClassMessage: </b>{{ .ClassMessage}}<br>
                                    <b>Recomendation: </b>{{ .Recomendation}}<br>
                                </p>
                            </td>
                        </tr>
                    {{end}}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    {{end}}
        <div class="row" style="border-top: #dee2e6 1px solid;padding-top: 10px;">
        <div class="col-12">
            <p>Copyright 2020 insidersec.io</p>

            <p>Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:</p>

            <p>The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.</p>

            <p>THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.</p>
        </div>
    </div>
</div>

</body>
</html>`
}

func downloadCss() error {
	resp, err := http.Get(CssURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(CssFile)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}
