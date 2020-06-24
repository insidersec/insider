package export

func GetTemplate(lang string) string {
	tpl := `
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
						<tr><td>High</td><td>&nbsp; {{ .High }}</td></tr>
						<tr><td>Medium</td><td>&nbsp; {{ .Medium }}</td></tr>
						<tr><td>Low</td><td>&nbsp; {{ .Low }}</td></tr>
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
        <div class='col-12'>
            <h6>DRA - Data Risk Analytics</h6>
            <div class='table-responsive'>
                <table class='table table-sm'>
                    <tbody>
                    {{ range .DRA}}
                        <tr>
                            <td class='user-select-all'>
                                <b>File :</b>{{ .FilePath}}<br>
                                <b>Dra :</b>{{ .Data}}<br>
                                <b>Type :</b>{{ .Type}}

                            </td>
                        </tr>
                    {{end}}
                    </tbody>
                </table>
            </div>
        </div>
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
                                    <b>CVSS  :</b>{{ .CVSS }}<br>
									<b>Rank :</b>{{ .Rank}}<br>
                                    <b>Class :</b>{{ .Class}}<br>
                                    <b>VulnerabilityID :</b>{{ .VulnerabilityID}}<br>
                                    <b>Method :</b>{{ .Method}}<br>
                                    <b>LongMessage :</b>{{ .LongMessage}}<br>
                                    <b>ClassMessage :</b>{{ .ClassMessage}}<br>
                                    <b>ShortMessage :</b>{{ .ShortMessage}}<br>
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
            <p><small>This Project are free software except otherwise stated. You can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
                <a href="http://www.gnu.org/licenses/">http://www.gnu.org/licenses/</a>.</small></p>
        </div>
    </div>
</div>

</body>
</html>`

	return tpl
}
