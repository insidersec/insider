package analyzers

import "github.com/insidersec/insider/models/reports"

func GetManifestPermission() []reports.ManifestPermission {
	var all []reports.ManifestPermission

	var obj reports.ManifestPermission
	obj.Title = "android.permission.SEND_SMS"
	obj.Description_pt_br = "Enviar Mensagens SMS"
	obj.Description_en = "Enviar Mensagens SMS"
	obj.Description_es = "Enviar Mensagens SMS"
	obj.Info_pt_br = "Permite a aplicação enviar Mensagens SMS. Aplicações maliciosas podem gastar dinheiro enviando mensagens sem sua confirmação."
	obj.Info_en = "Permite a aplicação enviar Mensagens SMS. Aplicações maliciosas podem gastar dinheiro enviando mensagens sem sua confirmação."
	obj.Info_es = "Permite a aplicação enviar Mensagens SMS. Aplicações maliciosas podem gastar dinheiro enviando mensagens sem sua confirmação."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.SEND_SMS_NO_CONFIRMATION"
	obj.Description_pt_br = "Enviar Mensagens SMS"
	obj.Description_en = "Send SMS messages"
	obj.Description_es = "Enviar mensajes SMS"
	obj.Info_pt_br = "Permite o envio de mensagens SMS via aplicativo de mensagens sem entrada ou confirmação do usuário."
	obj.Info_en = "Allows sending SMS messages via messaging application without user input or confirmation."
	obj.Info_es = "Permite enviar mensajes SMS a través de la aplicación de mensajería sin intervención o confirmación del usuario."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.CALL_PHONE"
	obj.Description_pt_br = "Ligar diretamente para números de telefone"
	obj.Description_en = "Call phone numbers directly"
	obj.Description_es = "Llamar directamente a los números"
	obj.Info_pt_br = "Permite que o aplicativo seja ativado sem a sua intervenção. Os aplicativos maliciosos podem gerar custos inesperados na sua conta telefônica. Observe que isso não permite que o aplicativo ligue para números de emergência."
	obj.Info_en = "Allows the application to be activated without your intervention. Malicious applications can generate unexpected costs on your phone bill. Note that this does not allow the application to call emergency numbers."
	obj.Info_es = "Permite que la aplicación se active sin su intervención. Las aplicaciones maliciosas pueden generar costos inesperados en su factura telefónica. Tenga en cuenta que esto no permite que la aplicación llame a números de emergencia."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.RECEIVE_SMS"
	obj.Description_pt_br = "Receber SMS"
	obj.Description_en = "Receive SMS"
	obj.Description_es = "Recibir SMS"
	obj.Info_pt_br = "Permite que o aplicativo receba e processe mensagens SMS. Os aplicativos maliciosos podem monitorar ou excluir suas mensagens sem você saber."
	obj.Info_en = "Allows the app to receive and process SMS messages. Malicious apps can monitor or delete your messages without you knowing it."
	obj.Info_es = "Permite que la aplicación reciba y procese mensajes SMS. Las aplicaciones maliciosas pueden monitorear o eliminar sus mensajes sin que usted lo sepa."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.RECEIVE_MMS"
	obj.Description_pt_br = "Receber MMS"
	obj.Description_en = "Receive MMS"
	obj.Description_es = "Recibir MMS"
	obj.Info_pt_br = "Permite que o aplicativo receba e processe mensagens MMS. Os aplicativos maliciosos podem monitorar ou excluir suas mensagens sem você saber."
	obj.Info_en = "Allows the app to receive and process MMS messages. Malicious apps can monitor or delete your messages without you knowing it."
	obj.Info_es = "Permite que la aplicación reciba y procese mensajes MMS. Las aplicaciones maliciosas pueden monitorear o eliminar sus mensajes sin que usted lo sepa."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.READ_SMS"
	obj.Description_pt_br = "Ler SMS ou MMS"
	obj.Description_en = "Read SMS or MMS"
	obj.Description_es = "Leer SMS o MMS"
	obj.Info_pt_br = "Permite que o aplicativo leia mensagens SMS guardadas no seu telefone ou cartão SIM. Os aplicativos maliciosos podem ler como suas mensagens confidenciais."
	obj.Info_en = "Allows the app to read SMS messages saved on your phone or SIM card. Malicious apps can read your confidential messages."
	obj.Info_es = "Permite que la aplicación lea mensajes SMS guardados en su teléfono o tarjeta SIM. Las aplicaciones maliciosas pueden leer sus mensajes confidenciales."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.WRITE_SMS"
	obj.Description_pt_br = "Editar SMS ou MMS"
	obj.Description_en = "Edit SMS or MMS"
	obj.Description_es = "Editar SMS o MMS"
	obj.Info_pt_br = "Permite que o aplicativo escreva mensagens SMS guardadas no seu telefone ou cartão SIM. Os aplicativos maliciosos podem excluir suas mensagens."
	obj.Info_en = "Allows the app to write SMS messages saved on your phone or SIM card. Malicious apps can delete your messages."
	obj.Info_es = "Permite que la aplicación escriba mensajes SMS guardados en su teléfono o tarjeta SIM. Las aplicaciones maliciosas pueden eliminar tus mensajes."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.RECEIVE_WAP_PUSH"
	obj.Description_pt_br = "Receber WAP"
	obj.Description_en = "Receive WAP"
	obj.Description_es = "Recibir WAP"
	obj.Info_pt_br = "Permite que o aplicativo receba e processe mensagens WAP. Os aplicativos maliciosos podem monitorar suas mensagens ou excluir-você sem saber."
	obj.Info_en = "Allows the app to receive and process WAP messages. Malicious apps can monitor your messages or delete you without knowing it."
	obj.Info_es = "Permite que la aplicación reciba y procese mensajes WAP. Las aplicaciones maliciosas pueden monitorear sus mensajes o eliminarlo sin saberlo."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.READ_CONTACTS"
	obj.Description_pt_br = "ler informações de contato"
	obj.Description_en = "read contact information"
	obj.Description_es = "leer información de contacto"
	obj.Info_pt_br = "Permite a aplicação ler todos os dados de contato (endereço) capturados no seu telefone. Aplicativos maliciosos podem usar isso para enviar seus dados para outras pessoas."
	obj.Info_en = "Allows the app to read all the contact (address) data captured on your phone. Malicious apps can use this to send your data to others."
	obj.Info_es = "Permite que la aplicación lea todos los datos de contacto (dirección) capturados en su teléfono. Las aplicaciones maliciosas pueden usar esto para enviar sus datos a otros."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.WRITE_CONTACTS"
	obj.Description_pt_br = "escrever informações de contato"
	obj.Description_en = "write contact information"
	obj.Description_es = "escribir información de contacto"
	obj.Info_pt_br = "Permite que o aplicativo modifique os dados de contato (endereço) capturados no seu telefone. Os aplicativos maliciosos podem usar isso para excluir ou modificar os dados de contato."
	obj.Info_en = "Allows the app to modify the contact (address) data captured on your phone. Malicious apps can use this to delete or modify contact data."
	obj.Info_es = "Permite que la aplicación modifique los datos de contacto (dirección) capturados en su teléfono. Las aplicaciones malintencionadas pueden usar esto para eliminar o modificar datos de contacto."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.READ_PROFILE"
	obj.Description_pt_br = "ler os dados do perfil pessoal do usuário"
	obj.Description_en = "read the user's personal profile data"
	obj.Description_es = "leer los datos del perfil personal del usuario"
	obj.Info_pt_br = "Permite que a Aplicação leia os dados pessoais do usuário."
	obj.Info_en = "Allows the Application to read the user's personal data."
	obj.Info_es = "Permite que la aplicación lea los datos personales del usuario."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.WRITE_PROFILE"
	obj.Description_pt_br = "escrever os dados do perfil pessoal do usuário"
	obj.Description_en = "write the user's personal profile data"
	obj.Description_es = "escribir los datos del perfil personal del usuario"
	obj.Info_pt_br = "Permite que oa aplicação escrita (mas não leia) leia os dados pessoais do usuário."
	obj.Info_en = "Allows the written application (but does not read) to read the user's personal data."
	obj.Info_es = "Permite que la aplicación escrita (pero no lee) lea los datos personales del usuario."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.READ_SOCIAL_STREAM"
	obj.Description_pt_br = "ler a partir do fluxo social do usuário"
	obj.Description_en = "read from the user's social stream"
	obj.Description_es = "leer del flujo social del usuario"
	obj.Info_pt_br = "Permite que o aplicativo leia a partir do fluxo social do usuário."
	obj.Info_en = "Allows the app to read from the user's social stream."
	obj.Info_es = "Permite que la aplicación lea de la transmisión social del usuario."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.WRITE_SOCIAL_STREAM"
	obj.Description_pt_br = "escrever a partir do fluxo social do usuário"
	obj.Description_en = "write from the user's social flow"
	obj.Description_es = "escribir desde el flujo social del usuario"
	obj.Info_pt_br = "Permite que o aplicativo escreva a partir do fluxo social do usuário."
	obj.Info_en = "Allows the app to write from the user's social stream."
	obj.Info_es = "Permite que la aplicación escriba desde la transmisión social del usuario."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.READ_CALENDAR"
	obj.Description_pt_br = "ler eventos da agenda"
	obj.Description_en = "read calendar events"
	obj.Description_es = "leer eventos del calendario"
	obj.Info_pt_br = "Permite a aplicação ler todos os eventos da agenda armazenados no seu telefone. Aplicativos maliciosos podem usar isso para enviar seus eventos da agenda para outras pessoas."
	obj.Info_en = "Allows the app to read all calendar events stored on your phone. Malicious apps can use this to send your calendar events to others."
	obj.Info_es = "Permite que la aplicación lea todos los eventos de calendario almacenados en su teléfono. Las aplicaciones maliciosas pueden usar esto para enviar sus eventos de calendario a otros."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.WRITE_CALENDAR"
	obj.Description_pt_br = "adicionar ou modificar eventos da agenda e enviar e-mails aos convidados"
	obj.Description_en = "add or modify calendar events and send guests emails"
	obj.Description_es = "agregar o modificar eventos del calendario y enviar correos electrónicos de invitados"
	obj.Info_pt_br = "Permite a aplicação adicionar ou alterar os eventos do seu calendário, o que pode enviar e-mails para convidados. Aplicativos maliciosos podem usar isso para excluir ou modificar os eventos da sua agenda ou enviar e-mails para os convidados. "
	obj.Info_en = "Allows the app to add or change events on your calendar, which can send emails to guests. Malicious apps can use this to delete or modify events on your calendar or send emails to guests."
	obj.Info_es = "Permite que la aplicación agregue o cambie eventos en su calendario, lo que puede enviar correos electrónicos a los invitados. Las aplicaciones maliciosas pueden usar esto para eliminar o modificar eventos en su calendario o enviar correos electrónicos a los invitados."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.READ_USER_DICTIONARY"
	obj.Description_pt_br = "ler dicionário definido pelo usuário"
	obj.Description_en = "read user-defined dictionary"
	obj.Description_es = "leer el diccionario definido por el usuario"
	obj.Info_pt_br = "Permite a aplicação palavras-chave exclusivas, nomes e frases particulares que o usuário possa ter armazenado no dicionário do usuário."
	obj.Info_en = "It allows the application of unique keywords, names and particular phrases that the user may have stored in the user dictionary."
	obj.Info_es = "Permite la aplicación de palabras clave únicas, nombres y frases particulares que el usuario puede haber almacenado en el diccionario del usuario."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.WRITE_USER_DICTIONARY"
	obj.Description_pt_br = "gravar no dicionário definido pelo usuário"
	obj.Description_en = "write to the user-defined dictionary"
	obj.Description_es = "escribir en el diccionario definido por el usuario"
	obj.Info_pt_br = "Permite a aplicação escrever novas palavras no dicionário do usuário."
	obj.Info_en = "Allows the app to write new words in the user dictionary."
	obj.Info_es = "Permite que la aplicación escriba nuevas palabras en el diccionario del usuario."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.READ_HISTORY_BOOKMARKS"
	obj.Description_pt_br = "ler histórico e os favoritos do navegador"
	obj.Description_en = "read browser history and bookmarks"
	obj.Description_es = "leer el historial del navegador y marcadores"
	obj.Info_pt_br = "Permite a aplicação ler todos os URLs que o navegador visita e todos os favoritos do navegador."
	obj.Info_en = "Allows the app to read all the URLs the browser visits and all the browser's favorites."
	obj.Info_es = "Permite que la aplicación lea todas las URL que visita el navegador y todos los favoritos del navegador."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.WRITE_HISTORY_BOOKMARKS"
	obj.Description_pt_br = "escrever histórico e os favoritos do navegador"
	obj.Description_en = "write browser history and bookmarks"
	obj.Description_es = "escribir el historial del navegador y marcadores"
	obj.Info_pt_br = "Permite a aplicação modificar o histórico ou os favoritos do navegador capturar no seu telefone. Os aplicativos maliciosos podem usar isso para excluir ou modificar os dados do seu navegador."
	obj.Info_en = "Allows the app to modify the browser history or bookmarks to capture on your phone. Malicious apps can use this to delete or modify your browser data."
	obj.Info_es = "Permite que la aplicación modifique el historial del navegador o los marcadores para capturar en su teléfono. Las aplicaciones maliciosas pueden usar esto para eliminar o modificar los datos de su navegador."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.SET_ALARM"
	obj.Description_pt_br = "definir alarme no despertador"
	obj.Description_en = "set alarm on alarm clock"
	obj.Description_es = "configurar alarma en despertador"
	obj.Info_pt_br = "Permite a aplicação definir um alarme no aplicativo de alarme instalado. Alguns aplicativos de alarme podem não implementar esse recurso."
	obj.Info_en = "Allows the app to set an alarm in the installed alarm application. Some alarm applications may not implement this feature."
	obj.Info_es = "Permite que la aplicación configure una alarma en la aplicación de alarma instalada. Es posible que algunas aplicaciones de alarma no implementen esta función."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.ACCESS_FINE_LOCATION"
	obj.Description_pt_br = "localização fina (GPS)"
	obj.Description_en = "fine location (GPS)"
	obj.Description_es = "buena ubicación (GPS)"
	obj.Info_pt_br = "Acesse fontes finas de localização, como o Sistema de Posicionamento Global no telefone, quando disponível. Aplicativos maliciosos podem usar isso para determinar onde você está e consumir energia adicional da bateria."
	obj.Info_en = "Access fine location sources, such as the Global Positioning System on the phone, when available. Malicious apps can use this to determine where you are and consume additional battery power."
	obj.Info_es = "Acceda a fuentes de ubicación precisas, como el Sistema de posicionamiento global en el teléfono, cuando esté disponible. Las aplicaciones maliciosas pueden usar esto para determinar dónde estás y consumir batería adicional."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.ACCESS_COARSE_LOCATION"
	obj.Description_pt_br = "localização aproximada (baseada na rede)"
	obj.Description_en = "approximate location (network based)"
	obj.Description_es = "ubicación aproximada (basada en la red)"
	obj.Info_pt_br = "Acesse fontes de localização aproximadas, como o banco de dados da rede móvel, para determinar uma localização aproximada do telefone, quando disponível. Aplicativos maliciosos podem usar isso para determinar aproximadamente onde você está."
	obj.Info_en = "Access approximate location sources, such as the mobile network database, to determine an approximate phone location, when available. Malicious apps can use this to roughly determine where you are."
	obj.Info_es = "Acceda a fuentes de ubicación aproximadas, como la base de datos de la red móvil, para determinar una ubicación aproximada del teléfono, cuando esté disponible. Las aplicaciones maliciosas pueden usar esto para determinar aproximadamente dónde se encuentra."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.ACCESS_MOCK_LOCATION"
	obj.Description_pt_br = "fontes falsas de localização para teste"
	obj.Description_en = "fake location sources for testing"
	obj.Description_es = "fuentes de ubicación falsas para pruebas"
	obj.Info_pt_br = "Crie fontes de localização falsas para teste. Aplicativos maliciosos podem usar isso para substituir uma localização e / ou status retornado por fontes de localização real, como GPS ou fornecedores de rede."
	obj.Info_en = "Create fake location sources for testing. Malicious apps can use this to replace a returned location and / or status with actual location sources, such as GPS or network providers."
	obj.Info_es = "Cree fuentes de ubicación falsas para realizar pruebas. Las aplicaciones maliciosas pueden usar esto para reemplazar una ubicación y / o estado devuelto con fuentes de ubicación reales, como GPS o proveedores de red."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.ACCESS_LOCATION_EXTRA_COMMANDS"
	obj.Description_pt_br = "acessar comandos adicionais de provedores de localização"
	obj.Description_en = "Access extra location provider commands"
	obj.Description_es = "acceder a comandos adicionales de proveedores de ubicación"
	obj.Info_pt_br = "Acesse os comandos adicionais fornecidos pelo provedor de localização. Os aplicativos maliciosos podem usar isso para interferir na operação do GPS ou em outras fontes de localização."
	obj.Info_en = "Access additional commands provided by the location provider. Malicious applications can use this to interfere with GPS operation or other sources of location."
	obj.Info_es = "Acceda a comandos adicionales proporcionados por el proveedor de ubicación. Las aplicaciones malintencionadas pueden usar esto para interferir con el funcionamiento del GPS u otras fuentes de ubicación."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.INSTALL_LOCATION_PROVIDER"
	obj.Description_pt_br = "permissão para instalar um provedor de localização"
	obj.Description_en = "permission to install a location provider"
	obj.Description_es = "permiso para instalar un proveedor de ubicación"
	obj.Info_pt_br = "Crie fontes de localização falsas para teste. Aplicativos maliciosos podem usar isso para substituir uma localização e / ou status retornado por fontes de localização real, como fornecedores de GPS ou rede, ou monitorar e reportar sua localização em uma fonte externa"
	obj.Info_en = "Create fake location sources for testing. Malicious applications can use this to replace a location and / or status returned with real location sources, such as GPS or network providers, or to monitor and report your location on an external source"
	obj.Info_es = "Cree fuentes de ubicación falsas para realizar pruebas. Las aplicaciones malintencionadas pueden usar esto para reemplazar una ubicación o estado devuelto con fuentes de ubicación reales, como GPS o proveedores de red, o monitorear e informar su ubicación en una fuente externa"
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.INTERNET"
	obj.Description_pt_br = "acesso total à Internet"
	obj.Description_en = "full internet access"
	obj.Description_es = "acceso completo a internet"
	obj.Info_pt_br = "Permite a aplicação criar soquetes de rede."
	obj.Info_en = "Allows the application to create network sockets."
	obj.Info_es = "Permite que la aplicación cree sockets de red."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.ACCESS_NETWORK_STATE"
	obj.Description_pt_br = "visualizar status da rede"
	obj.Description_en = "view network status"
	obj.Description_es = "ver el estado de la red"
	obj.Info_pt_br = "Permite a aplicação visualizar o status de todas as redes."
	obj.Info_en = "Allows the app to view the status of all networks."
	obj.Info_es = "Permite que la aplicación vea el estado de todas las redes."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.ACCESS_WIFI_STATE"
	obj.Description_pt_br = "visualizar status do Wi-Fi"
	obj.Description_en = "view Wi-Fi status"
	obj.Description_es = "ver el estado de Wi-Fi"
	obj.Info_pt_br = "Permite uma aplicação de visualização como informações sobre o status do Wi-Fi."
	obj.Info_en = "Allows a viewing application as information about the status of Wi-Fi."
	obj.Info_es = "Permite una aplicación de visualización como información sobre el estado de Wi-Fi."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.BLUETOOTH"
	obj.Description_pt_br = "Crie conexões Bluetooth"
	obj.Description_en = "Create Bluetooth connections"
	obj.Description_es = "Crear conexiones Bluetooth"
	obj.Info_pt_br = "Permite a aplicação visualizar a configuração do telefone Bluetooth local e fazer conexões com dispositivos emparelhados."
	obj.Info_en = "Allows the app to view the configuration of the local Bluetooth phone and to make connections to paired devices."
	obj.Info_es = "Permite que la aplicación vea la configuración del teléfono Bluetooth local y realice conexiones a dispositivos emparejados."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.NFC"
	obj.Description_pt_br = "Controlam a comunicação em campo próximo"
	obj.Description_en = "Control near-field communication"
	obj.Description_es = "Controlar la comunicación de campo cercano"
	obj.Info_pt_br = "Permite a aplicação comunicação com etiquetas, cartões e leitores de NFC (Near-Field Communication)."
	obj.Info_en = "It allows the application to communicate with NFC (Near-Field Communication) tags, cards and readers."
	obj.Info_es = "Permite que la aplicación se comunique con etiquetas, tarjetas y lectores NFC (Near-Field Communication)."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.USE_SIP"
	obj.Description_pt_br = "Faça / receba chamadas pela Internet"
	obj.Description_en = "Make / receive Internet calls"
	obj.Description_es = "Hacer / recibir llamadas por Internet"
	obj.Info_pt_br = "Permite a aplicação uso do serviço SIP para fazer / receber chamadas pela Internet."
	obj.Info_en = "Allows the application to use the SIP service to make / receive calls over the Internet."
	obj.Info_es = "Permite que la aplicación use el servicio SIP para hacer / recibir llamadas a través de Internet."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.ACCOUNT_MANAGER"
	obj.Description_pt_br = "Atua como o serviço de gerente de contas"
	obj.Description_en = "Acts as the account manager service"
	obj.Description_es = "Actúa como el servicio de administrador de cuenta"
	obj.Info_pt_br = "Permite a aplicação chamadas para Autenticadores de Conta"
	obj.Info_en = "Allows application to call Account Authenticators"
	obj.Info_es = "Permite que la aplicación llame a los Autenticadores de cuenta"
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.GET_ACCOUNTS"
	obj.Description_pt_br = "descobrir contas cadastradas"
	obj.Description_en = "discover registered accounts"
	obj.Description_es = "descubrir cuentas registradas"
	obj.Info_pt_br = "Permite a aplicação acesso a uma lista de contas identificadas pelo telefone."
	obj.Info_en = "Allows the app to access a list of accounts identified by the phone."
	obj.Info_es = "Permite que la aplicación acceda a una lista de cuentas identificadas por el teléfono."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.AUTHENTICATE_ACCOUNTS"
	obj.Description_pt_br = "atua como um autenticador de conta"
	obj.Description_en = "acts as an account authenticator"
	obj.Description_es = "actúa como un autenticador de cuenta"
	obj.Info_pt_br = "Permite a aplicação usar os recursos de autenticação de contas do Gerente de Contas, incluindo a criação de contas, bem como a identificação e configuração de suas senhas."
	obj.Info_en = "Allows the application to use the Account Manager's account authentication features, including creating accounts, as well as identifying and configuring their passwords."
	obj.Info_es = "Permite que la aplicación use las funciones de autenticación de cuentas del Administrador de cuentas, incluida la creación de cuentas, así como la identificación y configuración de sus contraseñas."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.USE_CREDENTIALS"
	obj.Description_pt_br = "use como credenciais de autenticação de uma conta"
	obj.Description_en = "use as authentication credentials for an account"
	obj.Description_es = "utilizar como credenciales de autenticación para una cuenta"
	obj.Info_pt_br = "Permite a aplicação tokens de autenticação de solicitação."
	obj.Info_en = "Allows the application of request authentication tokens."
	obj.Info_es = "Permite la aplicación de tokens de autenticación de solicitud."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.MANAGE_ACCOUNTS"
	obj.Description_pt_br = "gerenciar uma lista de contas"
	obj.Description_en = "manage a list of accounts"
	obj.Description_es = "administrar una lista de cuentas"
	obj.Info_pt_br = "Permite a aplicação operações como adicionar e remover contas e excluir sua senha."
	obj.Info_en = "Allows application operations such as adding and removing accounts and deleting your password."
	obj.Info_es = "Permite operaciones de aplicación como agregar y eliminar cuentas y eliminar su contraseña."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.MODIFY_AUDIO_SETTINGS"
	obj.Description_pt_br = "altere suas configurações de áudio"
	obj.Description_en = "change your audio settings"
	obj.Description_es = "cambiar la configuración de audio"
	obj.Info_pt_br = "Permite que o aplicativo modifique como configurações globais de áudio, como volume e roteamento."
	obj.Info_en = "Allows the app to modify global audio settings, such as volume and routing."
	obj.Info_es = "Permite que la aplicación modifique la configuración de audio global, como el volumen y el enrutamiento."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.RECORD_AUDIO"
	obj.Description_pt_br = "gravar áudio"
	obj.Description_en = "record audio"
	obj.Description_es = "grabar audio"
	obj.Info_pt_br = "Permite que o aplicativo acesse o caminho de gravação de áudio."
	obj.Info_en = "Allows the app to access the audio recording path."
	obj.Info_es = "Permite que la aplicación acceda a la ruta de grabación de audio."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.CAMERA"
	obj.Description_pt_br = "tire fotos e vídeos"
	obj.Description_en = "take photos and videos"
	obj.Description_es = "tomar fotos y videos"
	obj.Info_pt_br = "Permite que o aplicativo tire fotos e vídeos com a câmera. Isso permite que o aplicativo colete imagens que a câmera está vendo em qualquer momento."
	obj.Info_en = "Allows the app to take photos and videos with the camera. This allows the application to collect images that the camera is viewing at any time."
	obj.Info_es = "Permite que la aplicación tome fotos y videos con la cámara. Esto permite que la aplicación recopile imágenes que la cámara está viendo en cualquier momento."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.VIBRATE"
	obj.Description_pt_br = "vibrador de controle"
	obj.Description_en = "control vibrator"
	obj.Description_es = "vibrador de control"
	obj.Info_pt_br = "Permite uma aplicação de controle do vibrador."
	obj.Info_en = "It allows a vibrator control application."
	obj.Info_es = "Permite una aplicación de control de vibrador."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.FLASHLIGHT"
	obj.Description_pt_br = "lanterna de controle"
	obj.Description_en = "control flashlight"
	obj.Description_es = "control de linterna"
	obj.Info_pt_br = "Permite uma aplicação de controle da lanterna."
	obj.Info_en = "It allows a flashlight control application."
	obj.Info_es = "Permite una aplicación de control de linterna."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.ACCESS_USB"
	obj.Description_pt_br = "Acessar dispositivos USB"
	obj.Description_en = "Access USB devices"
	obj.Description_es = "Acceda a dispositivos USB"
	obj.Info_pt_br = "Permite a aplicação acesso a dispositivos USB."
	obj.Info_en = "Allows the app to access USB devices."
	obj.Info_es = "Permite que la aplicación acceda a dispositivos USB."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.HARDWARE_TEST"
	obj.Description_pt_br = "Hardware de teste"
	obj.Description_en = "Test hardware"
	obj.Description_es = "Prueba de hardware"
	obj.Info_pt_br = "Permite a aplicação controle de vários periféricos para fins de testes de hardware."
	obj.Info_en = "Allows application to control various peripherals for hardware testing purposes."
	obj.Info_es = "Permite que la aplicación controle varios periféricos para pruebas de hardware."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.PROCESS_OUTGOING_CALLS"
	obj.Description_pt_br = "Interceptar chamadas efetuadas"
	obj.Description_en = "Intercept outgoing calls"
	obj.Description_es = "Interceptar llamadas salientes"
	obj.Info_pt_br = "Permite que o aplicativo processe chamadas efetuadas e altere o número a ser discado. Os aplicativos maliciosos podem monitorar, redirecionar ou impedir chamadas efetuadas."
	obj.Info_en = "Allows the app to process outgoing calls and change the number to be dialed. Malicious applications can monitor, redirect or prevent outgoing calls."
	obj.Info_es = "Permite que la aplicación procese llamadas salientes y cambie el número a marcar. Las aplicaciones maliciosas pueden monitorear, redirigir o prevenir llamadas salientes."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.MODIFY_PHONE_STATE"
	obj.Description_pt_br = "Modificar status do telefone"
	obj.Description_en = "Modify phone status"
	obj.Description_es = "Modificar estado del teléfono"
	obj.Info_pt_br = "Permite a aplicação controle dos recursos de telefonia do dispositivo. Um aplicativo com permissão pode alternar entre redes, ligar e desligar o rádio do telefone e semelhante, sem nunca notificá-lo."
	obj.Info_en = "Allows the application to control the telephony resources of the device. An application with permission can switch between networks, turn the phone's radio on and off and the like, without ever notifying you."
	obj.Info_es = "Permite que la aplicación controle los recursos de telefonía del dispositivo. Una aplicación con permiso puede cambiar entre redes, encender y apagar la radio del teléfono y cosas por el estilo, sin avisarle nunca."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.READ_PHONE_STATE"
	obj.Description_pt_br = "Ler estado e identidade do telefone"
	obj.Description_en = "Read phone status and identity"
	obj.Description_es = "Leer el estado del teléfono y la identidad"
	obj.Info_pt_br = "Permite a aplicação acesso aos recursos de telefone do dispositivo. Um aplicativo com permissão pode determinar o número de telefone e o número de série deste telefone, se uma chamada estiver ativa, o número de chamada que está conectada etc . "
	obj.Info_en = "Allows the app to access the device's phone resources. An application with permission can determine the phone number and the serial number of this phone, if a call is active, the call number that is connected etc."
	obj.Info_es = "Permite que la aplicación acceda a los recursos del teléfono del dispositivo. Una aplicación con permiso puede determinar el número de teléfono y el número de serie de este teléfono, si una llamada está activa, el número de llamada que está conectado, etc."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.WRITE_EXTERNAL_STORAGE"
	obj.Description_pt_br = "Lê / modifica / apaga o conteúdo do cartão SD"
	obj.Description_en = "Reads / modifies / deletes the contents of the SD card"
	obj.Description_es = "Lee / modifica / elimina el contenido de la tarjeta SD"
	obj.Info_pt_br = "Permite uma aplicação de gravação no cartão SD."
	obj.Info_en = "Allows an application to write to the SD card."
	obj.Info_es = "Permite que una aplicación escriba en la tarjeta SD."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.READ_EXTERNAL_STORAGE"
	obj.Description_pt_br = "Ler o conteúdo do cartão SD"
	obj.Description_en = "Read the contents of the SD card"
	obj.Description_es = "Lee el contenido de la tarjeta SD"
	obj.Info_pt_br = "Permite uma aplicação de leitura do cartão SD."
	obj.Info_en = "Allows an application to read the SD card."
	obj.Info_es = "Permite que una aplicación lea la tarjeta SD."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.WRITE_SETTINGS"
	obj.Description_pt_br = "Modificar configurações globais do sistema"
	obj.Description_en = "Modify global system settings"
	obj.Description_es = "Modificar la configuración global del sistema"
	obj.Info_pt_br = "Permite a aplicação modificação dos dados de configuração do sistema. Os aplicativos maliciosos podem corromper a configuração do sistema."
	obj.Info_en = "Allows the application to modify the system configuration data. Malicious applications can corrupt the system configuration."
	obj.Info_es = "Permite que la aplicación modifique los datos de configuración del sistema. Las aplicaciones malintencionadas pueden dañar la configuración del sistema."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.WRITE_SECURE_SETTINGS"
	obj.Description_pt_br = "Modificar configurações de segurança do sistema"
	obj.Description_en = "Modify system security settings"
	obj.Description_es = "Modificar la configuración de seguridad del sistema"
	obj.Info_pt_br = "Permite a aplicação modificação de dados de configurações de segurança do sistema. Não é para ser usado com aplicativos comuns."
	obj.Info_en = "Allows application to modify system security settings data. It is not to be used with common applications."
	obj.Info_es = "Permite que la aplicación modifique los datos de configuración de seguridad del sistema. No se debe utilizar con aplicaciones comunes."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.WRITE_GSERVICES"
	obj.Description_pt_br = "Modifique o mapa de serviços do Google"
	obj.Description_en = "Modify the Google service map"
	obj.Description_es = "Modificar el mapa del servicio de Google"
	obj.Info_pt_br = "Permite a aplicação modificação ou mapa de serviços do Google. Não é para ser usado com aplicativos comuns."
	obj.Info_en = "Allows the application to modify or map Google services. It is not to be used with common applications."
	obj.Info_es = "Permite que la aplicación modifique o asigne servicios de Google. No se debe utilizar con aplicaciones comunes."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.EXPAND_STATUS_BAR"
	obj.Description_pt_br = "expandir / coletar barra de status"
	obj.Description_en = "expand / collect status bar"
	obj.Description_es = "expandir / recopilar barra de estado"
	obj.Info_pt_br = "Permite que o aplicativo expanda ou oculte uma barra de status."
	obj.Info_en = "Allows the app to expand or hide a status bar."
	obj.Info_es = "Permite que la aplicación expanda u oculte una barra de estado."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.GET_TASKS"
	obj.Description_pt_br = "recuperar aplicativos em execução"
	obj.Description_en = "recover running applications"
	obj.Description_es = "recuperar aplicaciones en ejecución"
	obj.Info_pt_br = "Permite que o aplicativo recupere informações sobre tarefas em execução recentes ou recentes. Pode permitir que aplicativos com intenções descubram informações privadas sobre outros aplicativos."
	obj.Info_en = "Allows the app to retrieve information about recently and recently running tasks. It can allow applications with intentions to discover private information about other applications."
	obj.Info_es = "Permite que la aplicación recupere información sobre tareas recientes y recientemente ejecutadas. Puede permitir que las aplicaciones con intenciones descubran información privada sobre otras aplicaciones."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.REORDER_TASKS"
	obj.Description_pt_br = "reordenar aplicativos em execução"
	obj.Description_en = "reorder running applications"
	obj.Description_es = "reordenar aplicaciones en ejecución"
	obj.Info_pt_br = "Permite a aplicação tarefas de movimentação para o primeiro plano e plano de fundo. Aplicativos maliciosos podem ser usados ​​para abrir para frente sem controle."
	obj.Info_en = "It allows the application of movement tasks for the foreground and background. Malicious applications can be used to open forward without control."
	obj.Info_es = "Permite la aplicación de tareas de movimiento para el primer plano y el fondo. Las aplicaciones maliciosas se pueden usar para abrir hacia adelante sin control."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.CHANGE_CONFIGURATION"
	obj.Description_pt_br = "altere as configurações da interface do usuário"
	obj.Description_en = "change user interface settings"
	obj.Description_es = "cambiar la configuración de la interfaz de usuario"
	obj.Info_pt_br = "Permite a aplicação alteração da configuração atual, como localidade ou tamanho geral da fonte."
	obj.Info_en = "Allows the application to change the current configuration, such as locality or general font size."
	obj.Info_es = "Permite que la aplicación cambie la configuración actual, como la localidad o el tamaño de fuente general."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.RESTART_PACKAGES"
	obj.Description_pt_br = "elimine processos em segundo plano"
	obj.Description_en = "eliminate background processes"
	obj.Description_es = "eliminar procesos en segundo plano"
	obj.Info_pt_br = "Permite a aplicação processos de remoção de segundo plano de outros aplicativos, mesmo se a memória não estiver baixa."
	obj.Info_en = "It allows the application to remove background processes from other applications, even if the memory is not low."
	obj.Info_es = "Permite que la aplicación elimine procesos en segundo plano de otras aplicaciones, incluso si la memoria no es baja."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.KILL_BACKGROUND_PROCESSES"
	obj.Description_pt_br = "elimine processos em segundo plano"
	obj.Description_en = "eliminate background processes"
	obj.Description_es = "eliminar procesos en segundo plano"
	obj.Info_pt_br = "Permite a aplicação processos de remoção de segundo plano de outros aplicativos, mesmo se a memória não estiver baixa."
	obj.Info_en = "Allows the application to remove background processes from other applications, even if memory is not low"
	obj.Info_es = "Permite que la aplicación elimine procesos en segundo plano de otras aplicaciones, incluso si la memoria no es baja"
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.FORCE_STOP_PACKAGES"
	obj.Description_pt_br = "forçar a parada de outras aplicações"
	obj.Description_en = "force other applications to stop"
	obj.Description_es = "obligar a otras aplicaciones a detenerse"
	obj.Info_pt_br = "Permite a aplicação parar outros aplicativos à força."
	obj.Info_en = "Allows the application to stop other applications forcibly."
	obj.Info_es = "Permite que la aplicación detenga otras aplicaciones por la fuerza."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.DUMP"
	obj.Description_pt_br = "recuperar status interno do sistema"
	obj.Description_en = "retrieve internal system status"
	obj.Description_es = "recuperar el estado del sistema interno"
	obj.Info_pt_br = "Permite que o aplicativo recupere o status interno do sistema. Os aplicativos maliciosos podem recuperar uma grande variedade de informações privadas e de segurança das quais eles geralmente nunca usam."
	obj.Info_en = "Allows the app to retrieve the internal status of the system. Malicious applications can recover a wide variety of private and security information that they usually never use."
	obj.Info_es = "Permite que la aplicación recupere el estado interno del sistema. Las aplicaciones maliciosas pueden recuperar una amplia variedad de información privada y de seguridad que generalmente nunca usan."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.SYSTEM_ALERT_WINDOW"
	obj.Description_pt_br = "exibir alertas no nível do sistema"
	obj.Description_en = "display system-level alerts"
	obj.Description_es = "mostrar alertas a nivel de sistema"
	obj.Info_pt_br = "Permite a aplicação janelas de alerta do sistema. Aplicativos maliciosos podem invadir uma tela inteira do telefone."
	obj.Info_en = "Allows the application of system alert windows. Malicious apps can invade an entire phone screen."
	obj.Info_es = "Permite la aplicación de ventanas de alerta del sistema. Las aplicaciones maliciosas pueden invadir la pantalla completa de un teléfono."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.SET_ANIMATION_SCALE"
	obj.Description_pt_br = "modifique a velocidade global da animação"
	obj.Description_en = "modify the overall speed of the animation"
	obj.Description_es = "modificar la velocidad general de la animación"
	obj.Info_pt_br = "Permite a aplicação alterar a velocidade global da animação (animações mais rápidas ou mais lentas) a qualquer momento."
	obj.Info_en = "Allows the app to change the overall speed of the animation (faster or slower animations) at any time."
	obj.Info_es = "Permite que la aplicación cambie la velocidad general de la animación (animaciones más rápidas o más lentas) en cualquier momento."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.PERSISTENT_ACTIVITY"
	obj.Description_pt_br = "faça o aplicativo sempre rodar"
	obj.Description_en = "always make the application run"
	obj.Description_es = "siempre haga que la aplicación se ejecute"
	obj.Info_pt_br = "Permite a aplicação tornar partes persistentes, para que o sistema não possa usar para outros aplicativos."
	obj.Info_en = "It allows the application to make parts persistent, so that the system cannot use it for other applications."
	obj.Info_es = "Permite que la aplicación haga partes persistentes, de modo que el sistema no pueda usarla para otras aplicaciones."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.GET_PACKAGE_SIZE"
	obj.Description_pt_br = "mede o espaço de armazenamento do aplicativo"
	obj.Description_en = "measures the storage space of the application"
	obj.Description_es = "mide el espacio de almacenamiento de la aplicación"
	obj.Info_pt_br = "Permite a aplicação recuperar seu código, tamanho de dados e cache"
	obj.Info_en = "Allows the application to recover its code, data size and cache"
	obj.Info_es = "Permite que la aplicación recupere su código, tamaño de datos y caché"
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.SET_PREFERRED_APPLICATIONS"
	obj.Description_pt_br = "definir aplicativos preferidos"
	obj.Description_en = "set favorite apps"
	obj.Description_es = "establecer aplicaciones favoritas"
	obj.Info_pt_br = "Permite a aplicação modificar seus aplicativos preferidos. Isso pode permitir que aplicativos maliciosos alterem silenciosamente os aplicativos executados, falsificando seus aplicativos existentes para coletar dados particulares de você."
	obj.Info_en = "Allows the app to modify your favorite applications. This can allow malicious applications to silently alter running applications, spoofing your existing applications to collect private data from you."
	obj.Info_es = "Permite que la aplicación modifique tus aplicaciones favoritas. Esto puede permitir que las aplicaciones maliciosas alteren silenciosamente las aplicaciones en ejecución, falsificando sus aplicaciones existentes para recopilar datos privados de usted."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.RECEIVE_BOOT_COMPLETED"
	obj.Description_pt_br = "iniciar automaticamente na inicialização"
	obj.Description_en = "automatically start at startup"
	obj.Description_es = "comenzar automáticamente al inicio"
	obj.Info_pt_br = "Permite a aplicação iniciar automaticamente assim que o sistema terminar. Isso pode levar mais tempo para iniciar o telefone e permitir que o aplicativo desacelere o telefone geral, sempre utilizado."
	obj.Info_en = "Allows the application to start automatically as soon as the system ends. This may take longer to start the phone and allow the application to slow down the general phone, which is always in use."
	obj.Info_es = "Permite que la aplicación se inicie automáticamente tan pronto como finalice el sistema. Esto puede llevar más tiempo para iniciar el teléfono y permitir que la aplicación desacelere el teléfono general, que siempre está en uso."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.BROADCAST_STICKY"
	obj.Description_pt_br = "enviar transmissão fixa"
	obj.Description_en = "send fixed transmission"
	obj.Description_es = "enviar transmisión fija"
	obj.Info_pt_br = "Permite uma aplicação de envio persistente, que permanece após o término da transmissão. Os aplicativos maliciosos podem tornar o telefone lento ou instável, fazendo com que ele use muita memória."
	obj.Info_en = "It allows a persistent sending application, which remains after the transmission is finished. Malicious applications can make your phone slow or unstable, causing it to use a lot of memory."
	obj.Info_es = "Permite una aplicación de envío persistente, que permanece una vez finalizada la transmisión. Las aplicaciones malintencionadas pueden hacer que su teléfono sea lento o inestable, haciendo que use mucha memoria."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.WAKE_LOCK"
	obj.Description_pt_br = "impeça o telefone de dormir"
	obj.Description_en = "prevent the phone from sleeping"
	obj.Description_es = "evitar que el teléfono duerma"
	obj.Info_pt_br = "Permite a aplicação impedir que o telefone entre no modo de suspensão."
	obj.Info_en = "Allows the app to prevent the phone from going to sleep."
	obj.Info_es = "Permite que la aplicación evite que el teléfono se vaya a dormir."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.SET_WALLPAPER"
	obj.Description_pt_br = "definir papel de parede"
	obj.Description_en = "set wallpaper"
	obj.Description_es = "establecer fondo de pantalla"
	obj.Info_pt_br = "Permite a aplicação definir o papel de parede do sistema."
	obj.Info_en = "Allows the app to set the system's wallpaper."
	obj.Info_es = "Permite que la aplicación configure el fondo de pantalla del sistema."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.SET_WALLPAPER_HINTS"
	obj.Description_pt_br = "definir dicas de tamanho de papel de parede"
	obj.Description_en = "set wallpaper size tips"
	obj.Description_es = "establecer consejos de tamaño de papel tapiz"
	obj.Info_pt_br = "Permite a aplicação definir como dicas de tamanho de papel de parede do sistema."
	obj.Info_en = "Allows the app to set system wallpaper size tips."
	obj.Info_es = "Permite que la aplicación establezca consejos de tamaño de fondo de pantalla del sistema."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.SET_TIME"
	obj.Description_pt_br = "definir tempo"
	obj.Description_en = "set time"
	obj.Description_es = "fijar tiempo"
	obj.Info_pt_br = "Permite uma aplicação de alteração de hora do telefone."
	obj.Info_en = "Allows a time change application on the phone."
	obj.Info_es = "Permite una aplicación de cambio de hora en el teléfono."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.SET_TIME_ZONE"
	obj.Description_pt_br = "definir fuso horário"
	obj.Description_en = "set time zone"
	obj.Description_es = "establecer zona horaria"
	obj.Info_pt_br = "Permite uma aplicação de alteração do horário do telefone."
	obj.Info_en = "Allows an application to change the phone time."
	obj.Info_es = "Permite que una aplicación cambie la hora del teléfono."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.MOUNT_UNMOUNT_FILESYSTEMS"
	obj.Description_pt_br = "montar e desmontar sistemas de arquivos"
	obj.Description_en = "mount and unmount file systems"
	obj.Description_es = "montar y desmontar sistemas de archivos"
	obj.Info_pt_br = "Permite aplicar e desmontar sistemas de arquivos para armazenamento removível."
	obj.Info_en = "Allows you to apply and unmount file systems for removable storage."
	obj.Info_es = "Le permite aplicar y desmontar sistemas de archivos para almacenamiento extraíble."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.MOUNT_FORMAT_FILESYSTEMS"
	obj.Description_pt_br = "formatar armazenamento externo"
	obj.Description_en = "format external storage"
	obj.Description_es = "formatear almacenamiento externo"
	obj.Info_pt_br = "Permite uma aplicação de formato de armazenamento removível."
	obj.Info_en = "It allows a removable storage format application."
	obj.Info_es = "Permite una aplicación de formato de almacenamiento extraíble."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.ASEC_ACCESS"
	obj.Description_pt_br = "Obter informações sobre armazenamento interno"
	obj.Description_en = "Get information about internal storage"
	obj.Description_es = "Obtenga información sobre el almacenamiento interno"
	obj.Info_pt_br = "Permite a aplicação obter informações sobre armazenamento interno."
	obj.Info_en = "Allows the app to get information about internal storage."
	obj.Info_es = "Permite que la aplicación obtenga información sobre el almacenamiento interno."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.ASEC_CREATE"
	obj.Description_pt_br = "criar armazenamento interno"
	obj.Description_en = "create internal storage"
	obj.Description_es = "crear almacenamiento interno"
	obj.Info_pt_br = "Permite a aplicação criar armazenamento interno."
	obj.Info_en = "Allows the app to create internal storage."
	obj.Info_es = "Permite que la aplicación cree almacenamiento interno."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.ASEC_DESTROY"
	obj.Description_pt_br = "destruição do armazenamento interno"
	obj.Description_en = "destruction of internal storage"
	obj.Description_es = "destrucción del almacenamiento interno"
	obj.Info_pt_br = "Permite uma aplicação de destruição do armazenamento interno."
	obj.Info_en = "Enables an application to destroy internal storage."
	obj.Info_es = "Permite que una aplicación destruya el almacenamiento interno."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.ASEC_MOUNT_UNMOUNT"
	obj.Description_pt_br = "montar / desmontar armazenamento interno"
	obj.Description_en = "mount / unmount internal storage"
	obj.Description_es = "montar / desmontar almacenamiento interno"
	obj.Info_pt_br = "Permite a aplicação montar / desmontar armazenamento interno."
	obj.Info_en = "Allows the application to mount / unmount internal storage."
	obj.Info_es = "Permite que la aplicación monte / desmonte almacenamiento interno."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.ASEC_RENAME"
	obj.Description_pt_br = "renomear armazenamento interno"
	obj.Description_en = "rename internal storage"
	obj.Description_es = "renombrar almacenamiento interno"
	obj.Info_pt_br = "Permite uma aplicação de renomear armazenamento interno."
	obj.Info_en = "Allows an application to rename internal storage."
	obj.Info_es = "Permite que una aplicación cambie el nombre del almacenamiento interno."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.DISABLE_KEYGUARD"
	obj.Description_pt_br = "desativar bloqueio de teclas"
	obj.Description_en = "disable key lock"
	obj.Description_es = "desactivar bloqueo de teclas"
	obj.Info_pt_br = "Permite a aplicação alteração de bloqueio de teclas e segurança de senha associada. Um exemplo legítimo disso é o telefone desativado ou o bloqueio de teclas para receber uma chamada telefônica e, em seguida, reativar ou bloquear as teclas quando a chamada está concluída. "
	obj.Info_en = "Allows the application to change key lock and associated password security. A legitimate example of this is the disabled phone or key lock to receive a phone call and then reactivate or lock the keys when the call is complete."
	obj.Info_es = "Permite que la aplicación cambie el bloqueo de teclas y la seguridad de contraseña asociada. Un ejemplo legítimo de esto es el teléfono deshabilitado o el bloqueo de teclas para recibir una llamada telefónica y luego reactivar o bloquear las teclas cuando se completa la llamada."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.READ_SYNC_SETTINGS"
	obj.Description_pt_br = "leia configurações de sincronização"
	obj.Description_en = "read sync settings"
	obj.Description_es = "leer la configuración de sincronización"
	obj.Info_pt_br = "Permite a aplicação leitura como configurações de sincronização, como se a sincronização estiver ativada para contatos."
	obj.Info_en = "Allows the application to read as synchronization settings, as if synchronization is enabled for contacts."
	obj.Info_es = "Permite que la aplicación lea como configuración de sincronización, como si la sincronización estuviera habilitada para los contactos."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.WRITE_SYNC_SETTINGS"
	obj.Description_pt_br = "escrever configurações de sincronização"
	obj.Description_en = "write synchronization settings"
	obj.Description_es = "escribir configuraciones de sincronización"
	obj.Info_pt_br = "Permite a aplicação modificação como configurações de sincronização, como se a sincronização estiver ativada para contatos."
	obj.Info_en = "Allows the application to modify as synchronization settings, as if synchronization is enabled for contacts."
	obj.Info_es = "Permite que la aplicación se modifique como configuración de sincronización, como si la sincronización estuviera habilitada para los contactos."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.READ_SYNC_STATS"
	obj.Description_pt_br = "leia estatísticas de sincronização"
	obj.Description_en = "read sync statistics"
	obj.Description_es = "leer estadísticas de sincronización"
	obj.Info_pt_br = "Permite a aplicação leitura como estatísticas de sincronização; por exemplo, o histórico de sincronizações que ocorre."
	obj.Info_en = "Allows the application to read as synchronization statistics; for example, the synchronization history that occurs."
	obj.Info_es = "Permite que la aplicación lea como estadísticas de sincronización; por ejemplo, el historial de sincronización que ocurre."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.WRITE_APN_SETTINGS"
	obj.Description_pt_br = "escrever configurações do nome do ponto de acesso"
	obj.Description_en = "write access point name settings"
	obj.Description_es = "escribir la configuración del nombre del punto de acceso"
	obj.Info_pt_br = "Permite uma aplicação de modificação como configurações do APN, como Proxy e Porta de qualquer APN."
	obj.Info_en = "It allows a modification application such as APN settings, such as Proxy and Port of any APN."
	obj.Info_es = "Permite una aplicación de modificación, como la configuración de APN, como Proxy y Puerto de cualquier APN."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.SUBSCRIBED_FEEDS_READ"
	obj.Description_pt_br = "leia feeds inscritos"
	obj.Description_en = "read subscribed feeds"
	obj.Description_es = "leer feeds suscritos"
	obj.Info_pt_br = "Permite a aplicação receber detalhes sobre os feeds sincronizados no momento."
	obj.Info_en = "Allows the app to receive details about the feeds currently synced."
	obj.Info_es = "Permite que la aplicación reciba detalles sobre los feeds actualmente sincronizados."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.SUBSCRIBED_FEEDS_WRITE"
	obj.Description_pt_br = "escreve feeds inscritos"
	obj.Description_en = "writes subscribed feeds"
	obj.Description_es = "escribe feeds suscritos"
	obj.Info_pt_br = "Permite a aplicação modificar seus feeds sincronizados no momento. Isso pode permitir que um aplicativo com intenção de alterar seus feeds sincronizados."
	obj.Info_en = "Allows the app to modify your currently synced feeds. This can allow an application intent on changing its synchronized feeds."
	obj.Info_es = "Permite que la aplicación modifique tus feeds sincronizados actualmente. Esto puede permitir que una aplicación intente cambiar sus feeds sincronizados."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.CHANGE_NETWORK_STATE"
	obj.Description_pt_br = "alterar a conectividade da rede"
	obj.Description_en = "change network connectivity"
	obj.Description_es = "cambiar la conectividad de red"
	obj.Info_pt_br = "Permite a aplicação alteração ou estado da conexão de rede."
	obj.Info_en = "Allows the application to change or state the network connection."
	obj.Info_es = "Permite que la aplicación cambie o establezca la conexión de red."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.CHANGE_WIFI_STATE"
	obj.Description_pt_br = "alterar o status do Wi-Fi"
	obj.Description_en = "change Wi-Fi status"
	obj.Description_es = "cambiar el estado de Wi-Fi"
	obj.Info_pt_br = "Permite a aplicação conectar e desconectar pontos de acesso Wi-Fi e fazer alterações nas redes Wi-Fi configuradas."
	obj.Info_en = "Allows the app to connect and disconnect Wi-Fi access points and make changes to configured Wi-Fi networks."
	obj.Info_es = "Permite que la aplicación se conecte y desconecte puntos de acceso Wi-Fi y realice cambios en las redes Wi-Fi configuradas."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.CHANGE_WIFI_MULTICAST_STATE"
	obj.Description_pt_br = "permite a recepção Wi-Fi Multicast"
	obj.Description_en = "allows Wi-Fi Multicast reception"
	obj.Description_es = "permite la recepción de Wi-Fi Multicast"
	obj.Info_pt_br = "Permite a aplicação recebimento de pacotes não endereçados diretamente ao seu dispositivo. Isso pode ser útil na descoberta de serviços oferecidos nas ameaças. Ele consome mais energia do que o modo não multicast."
	obj.Info_en = "Allows the application to receive packets not addressed directly to your device. This can be useful in discovering services offered in threats. It consumes more energy than non-multicast mode."
	obj.Info_es = "Permite que la aplicación reciba paquetes no dirigidos directamente a su dispositivo. Esto puede ser útil para descubrir servicios ofrecidos en amenazas. Consume más energía que el modo sin multidifusión."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.BLUETOOTH_ADMIN"
	obj.Description_pt_br = "administração bluetooth"
	obj.Description_en = "bluetooth administration"
	obj.Description_es = "administración de bluetooth"
	obj.Info_pt_br = "Permite a aplicação configurar o telefone Bluetooth local e descobrir e procurar com dispositivos remotos."
	obj.Info_en = "Allows the app to configure the local Bluetooth phone and to discover and search with remote devices."
	obj.Info_es = "Permite que la aplicación configure el teléfono Bluetooth local y descubra y busque con dispositivos remotos."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.CLEAR_APP_CACHE"
	obj.Description_pt_br = "exclua todos os dados do cache do aplicativo"
	obj.Description_en = "delete all data from the application cache"
	obj.Description_es = "eliminar todos los datos del caché de la aplicación"
	obj.Info_pt_br = "Permite a aplicação armazenamento telefônico gratuito excluindo arquivos no diretório de cache do aplicativo. O acesso é muito restrito ao processo do sistema."
	obj.Info_en = "Allows the application to free phone storage by excluding files in the application's cache directory. Access is very restricted to the system process."
	obj.Info_es = "Permite que la aplicación libere el almacenamiento del teléfono al excluir archivos en el directorio de caché de la aplicación. El acceso está muy restringido al proceso del sistema."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.READ_LOGS"
	obj.Description_pt_br = "ler dados confidenciais do log"
	obj.Description_en = "read sensitive data from the log"
	obj.Description_es = "leer datos confidenciales del registro"
	obj.Info_pt_br = "Permite uma aplicação de leitura dos vários arquivos de log do sistema. Isso permite descobrir informações gerais sobre quem você está fazendo com o telefone, incluindo possíveis informações pessoais ou privadas."
	obj.Info_en = "It allows an application to read the various system log files. This allows you to discover general information about who you are doing with the phone, including possible personal or private information."
	obj.Info_es = "Permite que una aplicación lea los diversos archivos de registro del sistema. Esto le permite descubrir información general sobre quién está haciendo con el teléfono, incluida la posible información personal o privada."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.SET_DEBUG_APP"
	obj.Description_pt_br = "ativar a depuração do aplicativo"
	obj.Description_en = "enable application debugging"
	obj.Description_es = "habilitar depuración de aplicaciones"
	obj.Info_pt_br = "Permite a aplicação ativação da depuração para outro aplicativo. Aplicativos maliciosos podem usar isso para matar outros aplicativos."
	obj.Info_en = "Allows the application to activate debugging for another application. Malicious apps can use this to kill other apps."
	obj.Info_es = "Permite que la aplicación active la depuración para otra aplicación. Las aplicaciones maliciosas pueden usar esto para matar otras aplicaciones."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.SET_PROCESS_LIMIT"
	obj.Description_pt_br = "número limite de processos em execução"
	obj.Description_en = "limit number of running processes"
	obj.Description_es = "limitar el número de procesos en ejecución"
	obj.Info_pt_br = "Permite a aplicação controle do número máximo de processos que serão executados. Nunca é necessário para aplicativos comuns."
	obj.Info_en = "It allows the application to control the maximum number of processes that will be executed. It is never necessary for common applications."
	obj.Info_es = "Permite que la aplicación controle el número máximo de procesos que se ejecutarán. Nunca es necesario para aplicaciones comunes."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.SET_ALWAYS_FINISH"
	obj.Description_pt_br = "fecha todos os aplicativos no segundo plano"
	obj.Description_en = "closes all applications in the background"
	obj.Description_es = "cierra todas las aplicaciones en segundo plano"
	obj.Info_pt_br = "Permite a aplicação controle como atividades sempre concluídas da mesma forma que entram no segundo plano. Nunca são necessárias para aplicativos comuns."
	obj.Info_en = "It allows the control application as activities always completed in the same way that they enter the background. They are never needed for common applications."
	obj.Info_es = "Permite la aplicación de control ya que las actividades siempre se completan de la misma manera que ingresan al fondo. Nunca son necesarios para aplicaciones comunes."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.SIGNAL_PERSISTENT_PROCESSES"
	obj.Description_pt_br = "envia sinais do Linux para aplicativos"
	obj.Description_en = "sends Linux signals to applications"
	obj.Description_es = "envía señales de Linux a las aplicaciones"
	obj.Info_pt_br = "Permite que o aplicativo solicite que o sinal seja enviado a todos os processos persistentes."
	obj.Info_en = "Allows the app to request that the signal be sent to all persistent processes."
	obj.Info_es = "Permite que la aplicación solicite que se envíe la señal a todos los procesos persistentes."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.DIAGNOSTIC"
	obj.Description_pt_br = "leitura / gravação em recursos pertencentes a diag"
	obj.Description_en = "read / write to resources belonging to diag"
	obj.Description_es = "leer / escribir en recursos pertenecientes a diag"
	obj.Info_pt_br = "Permite a aplicação leitura e gravação em qualquer recurso pertencente ao grupo diag; por exemplo, arquivos em / dev. Isso pode afetar a estabilidade e a segurança do sistema. Isso deve ser usado SOMENTE para diagnósticos de hardware usados ​​pelo fabricante ou operador"
	obj.Info_en = "Allows the application to read and write to any resource belonging to the diag group; for example, files in / dev. This can affect the stability and security of the system. This should ONLY be used for hardware diagnostics used by the manufacturer or operator"
	obj.Info_es = "Permite que la aplicación lea y escriba en cualquier recurso que pertenezca al grupo diag; por ejemplo, archivos en / dev. Esto puede afectar la estabilidad y la seguridad del sistema. Esto SOLO debe usarse para diagnósticos de hardware utilizados por el fabricante u operador"
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.STATUS_BAR"
	obj.Description_pt_br = "alterar ou modificar a barra de status"
	obj.Description_en = "change or modify the status bar"
	obj.Description_es = "cambiar o modificar la barra de estado"
	obj.Info_pt_br = "Permite que o aplicativo desative a barra de status ou adicione e remova ícones do sistema."
	obj.Info_en = "Allows the app to disable the status bar or to add and remove icons from the system."
	obj.Info_es = "Permite que la aplicación desactive la barra de estado o que agregue y elimine íconos del sistema."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.STATUS_BAR_SERVICE"
	obj.Description_pt_br = "barra de status"
	obj.Description_en = "status bar"
	obj.Description_es = "barra de estado"
	obj.Info_pt_br = "Permite a aplicação ser uma barra de status."
	obj.Info_en = "Allows the application to be a status bar."
	obj.Info_es = "Permite que la aplicación sea una barra de estado."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.FORCE_BACK"
	obj.Description_pt_br = "forçar o fechamento do aplicativo"
	obj.Description_en = "force the application to close"
	obj.Description_es = "forzar el cierre de la aplicación"
	obj.Info_pt_br = "Permite a aplicação qualquer atividade que esteja no primeiro plano a fechar e voltar. Nunca deve ser necessário para aplicativos comuns."
	obj.Info_en = "The application allows any activity that is in the foreground to close and return. It should never be necessary for common applications."
	obj.Info_es = "La aplicación permite que cualquier actividad que esté en primer plano se cierre y regrese. Nunca debería ser necesario para aplicaciones comunes."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.UPDATE_DEVICE_STATS"
	obj.Description_pt_br = "modificar estatísticas da bateria"
	obj.Description_en = "modify battery statistics"
	obj.Description_es = "modificar las estadísticas de la batería"
	obj.Info_pt_br = "Permite alterar estatísticas coletadas da bateria. Não é para ser usado com aplicativos comuns."
	obj.Info_en = "Allows you to change statistics collected from the battery. It is not to be used with common applications."
	obj.Info_es = "Le permite cambiar las estadísticas recopiladas de la batería. No se debe utilizar con aplicaciones comunes."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.INTERNAL_SYSTEM_WINDOW"
	obj.Description_pt_br = "exibidas janelas não autorizadas"
	obj.Description_en = "unauthorized windows are displayed"
	obj.Description_es = "se muestran ventanas no autorizadas"
	obj.Info_pt_br = "Permite a criação de janelas que devem ser usadas pela interface do usuário do sistema interno. Não é para ser usado com aplicativos comuns."
	obj.Info_en = "It allows the creation of windows to be used by the internal system's user interface. It is not to be used with common applications."
	obj.Info_es = "Permite la creación de ventanas para ser utilizada por la interfaz de usuario del sistema interno. No se debe utilizar con aplicaciones comunes."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.MANAGE_APP_TOKENS"
	obj.Description_pt_br = "gerenciar tokens de aplicativos"
	obj.Description_en = "manage application tokens"
	obj.Description_es = "administrar tokens de aplicaciones"
	obj.Info_pt_br = "Permite que os aplicativos criem e gerem seus tokens únicos, ignorando sua ordem Z comum. Nunca deve ser necessário para aplicativos comuns."
	obj.Info_en = "Allows applications to create and generate their unique tokens, ignoring their common Z order. It should never be necessary for common applications."
	obj.Info_es = "Permite que las aplicaciones creen y generen sus tokens únicos, ignorando su orden Z común. Nunca debería ser necesario para aplicaciones comunes."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.INJECT_EVENTS"
	obj.Description_pt_br = "pressione as teclas e os botões de controle"
	obj.Description_en = "press keys and control buttons"
	obj.Description_es = "presione teclas y botones de control"
	obj.Info_pt_br = "Permite a aplicação entregar seus próprios eventos de entrada (pressionamentos de tecla, etc.) para outros aplicativos. Aplicativos maliciosos podem usar isso para controlar o telefone."
	obj.Info_en = "Allows the app to deliver its own input events (key presses, etc.) to other apps. Malicious apps can use this to control the phone."
	obj.Info_es = "Permite que la aplicación entregue sus propios eventos de entrada (pulsaciones de teclas, etc.) a otras aplicaciones. Las aplicaciones maliciosas pueden usar esto para controlar el teléfono."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.SET_ACTIVITY_WATCHER"
	obj.Description_pt_br = "monitora e controla todo o lançamento de aplicativos"
	obj.Description_en = "monitors and controls all application launches"
	obj.Description_es = "monitorea y controla todos los lanzamientos de aplicaciones"
	obj.Info_pt_br = "Permite a aplicação monitoramento e controle de como o sistema inicia atividades. Como aplicativos maliciosos podem comprometer completamente o sistema. Essa permissão é necessária apenas para o desenvolvimento, nunca para o uso comum do telefone."
	obj.Info_en = "It allows the application to monitor and control how the system starts activities. How malicious applications can completely compromise the system. This permission is only necessary for development, never for ordinary telephone use."
	obj.Info_es = "Permite que la aplicación monitoree y controle cómo el sistema inicia actividades. Cómo las aplicaciones maliciosas pueden comprometer completamente el sistema. Este permiso solo es necesario para el desarrollo, nunca para el uso ordinario del teléfono."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.SHUTDOWN"
	obj.Description_pt_br = "desligamento parcial"
	obj.Description_en = "partial shutdown"
	obj.Description_es = "cierre parcial"
	obj.Info_pt_br = "Colocar ou gerenciar atividades em um estado de desligamento. Não execute um desligamento completo."
	obj.Info_en = "Put or manage activities in a shutdown state. Do not perform a complete shutdown."
	obj.Info_es = "Poner o gestionar actividades en estado de apagado. No realice un apagado completo."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.STOP_APP_SWITCHES"
	obj.Description_pt_br = "impedir trocas de aplicativos"
	obj.Description_en = "prevent application exchanges"
	obj.Description_es = "evitar intercambios de aplicaciones"
	obj.Info_pt_br = "Previna o usuário de alterar para outra aplicação."
	obj.Info_en = "Prevent the user from changing to another application."
	obj.Info_es = "Evitar que el usuario cambie a otra aplicación."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.READ_INPUT_STATE"
	obj.Description_pt_br = "registre o que você digita e as ações que executam"
	obj.Description_en = "record what you type and the actions you take"
	obj.Description_es = "registra lo que escribes y las acciones que tomas"
	obj.Info_pt_br = "Permite que os aplicativos observem como as teclas que você pressiona, mesmo ao interagir com outro aplicativo (como digitar uma senha). Nunca deve ser necessário para aplicativos comuns."
	obj.Info_en = "Allows applications to observe the keys you press, even when interacting with another application (such as entering a password). It should never be necessary for common applications."
	obj.Info_es = "Permite que las aplicaciones observen las teclas que presiona, incluso cuando interactúa con otra aplicación (como ingresar una contraseña). Nunca debería ser necesario para aplicaciones comunes."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.BIND_INPUT_METHOD"
	obj.Description_pt_br = "vincular a um método de entrada"
	obj.Description_en = "link to an input method"
	obj.Description_es = "enlace a un método de entrada"
	obj.Info_pt_br = "Permite que o proprietário vincule à interface de nível superior de um método de entrada. Nunca deve ser necessário para aplicativos comuns."
	obj.Info_en = "Allows the owner to link to the top level interface of an input method. It should never be necessary for common applications."
	obj.Info_es = "Permite al propietario vincular a la interfaz de nivel superior de un método de entrada. Nunca debería ser necesario para aplicaciones comunes."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.BIND_WALLPAPER"
	obj.Description_pt_br = "vincular ao papel de parede"
	obj.Description_en = "link to wallpaper"
	obj.Description_es = "enlace al fondo de pantalla"
	obj.Info_pt_br = "Permite ao proprietário vincular-se à interface de nível superior do papel de parede. Nunca deve ser necessário para aplicativos comuns."
	obj.Info_en = "Allows the owner to link to the top-level wallpaper interface. It should never be necessary for common applications."
	obj.Info_es = "Permite al propietario vincular a la interfaz de fondo de pantalla de nivel superior. Nunca debería ser necesario para aplicaciones comunes."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.BIND_DEVICE_ADMIN"
	obj.Description_pt_br = "interaja com o administrador do dispositivo"
	obj.Description_en = "interact with the device administrator"
	obj.Description_es = "interactuar con el administrador del dispositivo"
	obj.Info_pt_br = "Permite que o proprietário envie intenções ao administrador de dispositivos. Nunca deve ser necessário para aplicativos comuns."
	obj.Info_en = "Allows the owner to send intentions to the device administrator. It should never be necessary for common applications."
	obj.Info_es = "Permite al propietario enviar intenciones al administrador del dispositivo. Nunca debería ser necesario para aplicaciones comunes."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.SET_ORIENTATION"
	obj.Description_pt_br = "alterar orientação da tela"
	obj.Description_en = "change screen orientation"
	obj.Description_es = "cambiar la orientación de la pantalla"
	obj.Info_pt_br = "Permite a aplicação alteração da tela a qualquer momento. Nunca deve ser necessário para aplicativos comuns."
	obj.Info_en = "Allows the application to change the screen at any time. It should never be necessary for common applications."
	obj.Info_es = "Permite que la aplicación cambie la pantalla en cualquier momento. Nunca debería ser necesario para aplicaciones comunes."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.INSTALL_PACKAGES"
	obj.Description_pt_br = "instale aplicativos diretamente"
	obj.Description_en = "install apps directly"
	obj.Description_es = "instalar aplicaciones directamente"
	obj.Info_pt_br = "Permite a aplicação instalação de pacotes novos ou de uso Android. Aplicativos maliciosos podem usar isso para adicionar novos aplicativos com aplicativos arbitrariamente poderosos."
	obj.Info_en = "Allows the application to install new packages or use Android. Malicious apps can use this to add new apps with arbitrarily powerful apps."
	obj.Info_es = "Permite que la aplicación instale nuevos paquetes o use Android. Las aplicaciones maliciosas pueden usar esto para agregar nuevas aplicaciones con aplicaciones arbitrariamente potentes."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.REQUEST_INSTALL_PACKAGES"
	obj.Description_pt_br = "Permite uma aplicação de solicitação de instalação de pacotes."
	obj.Description_en = "Enables a package installation request application."
	obj.Description_es = "Habilita una aplicación de solicitud de instalación de paquete."
	obj.Info_pt_br = "Aplicativos maliciosos podem usar isso para tentar induzir os usuários a instalar pacotes maliciosos adicionais."
	obj.Info_en = "Malicious applications can use this to try to trick users into installing additional malicious packages."
	obj.Info_es = "Las aplicaciones maliciosas pueden usar esto para tratar de engañar a los usuarios para que instalen paquetes maliciosos adicionales."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.CLEAR_APP_USER_DATA"
	obj.Description_pt_br = "apague os dados de outras aplicações"
	obj.Description_en = "erase data from other applications"
	obj.Description_es = "borrar datos de otras aplicaciones"
	obj.Info_pt_br = "Permite a aplicação dados claros do usuário."
	obj.Info_en = "Allows application of clear user data."
	obj.Info_es = "Permite la aplicación de datos de usuario claros."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.DELETE_CACHE_FILES"
	obj.Description_pt_br = "excluindo os caches de outros aplicativos"
	obj.Description_en = "excluding caches from other applications"
	obj.Description_es = "excluyendo cachés de otras aplicaciones"
	obj.Info_pt_br = "Permite a aplicação excluir arquivos de cache."
	obj.Info_en = "Allows the app to delete cache files."
	obj.Info_es = "Permite que la aplicación elimine archivos de caché."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.DELETE_PACKAGES"
	obj.Description_pt_br = "excluir aplicativos"
	obj.Description_en = "delete apps"
	obj.Description_es = "eliminar aplicaciones"
	obj.Info_pt_br = "Permite a aplicação exclusão de pacotes do Android. Aplicativos maliciosos podem usar isso para excluir aplicativos importantes."
	obj.Info_en = "Allows the application to delete packages from Android. Malicious apps can use this to delete important apps."
	obj.Info_es = "Permite que la aplicación elimine paquetes de Android. Las aplicaciones malintencionadas pueden usar esto para eliminar aplicaciones importantes."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.MOVE_PACKAGE"
	obj.Description_pt_br = "Mover recursos do aplicativo"
	obj.Description_en = "Move application resources"
	obj.Description_es = "Mover recursos de la aplicación"
	obj.Info_pt_br = "Permite a aplicação recursos de aplicativos de mídia interna para externa e vice-versa."
	obj.Info_en = "Allows application resources from internal to external media applications and vice versa."
	obj.Info_es = "Permite recursos de aplicaciones de aplicaciones de medios internos a externos y viceversa."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.CHANGE_COMPONENT_ENABLED_STATE"
	obj.Description_pt_br = "ativar ou desativar componentes do aplicativo"
	obj.Description_en = "enable or disable application components"
	obj.Description_es = "activar o desactivar componentes de la aplicación"
	obj.Info_pt_br = "Permite a aplicação alteração se um componente de outro aplicativo for ativado ou desativado. Aplicativos maliciosos podem usar-lo para ativar recursos importantes do telefone. É importante ter cuidado com permissões, pois é possível incluir componentes do aplicativo estado inutilizável, inconsistente ou instável"
	obj.Info_en = "Allows the application to change if a component of another application is enabled or disabled. Malicious apps can use it to activate important phone features. It is important to be careful with permissions as it is possible to include application components that are unusable, inconsistent or unstable"
	obj.Info_es = "Permite que la aplicación cambie si un componente de otra aplicación está habilitado o deshabilitado. Las aplicaciones maliciosas pueden usarlo para activar funciones importantes del teléfono. Es importante tener cuidado con los permisos, ya que es posible incluir componentes de la aplicación que sean inutilizables, inconsistentes o inestables."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.ACCESS_SURFACE_FLINGER"
	obj.Description_pt_br = "acesse o SurfaceFlinger"
	obj.Description_en = "access SurfaceFlinger"
	obj.Description_es = "acceder a SurfaceFlinger"
	obj.Info_pt_br = "Permite que o aplicativo use os recursos de nível inferior do SurfaceFlinger."
	obj.Info_en = "Allows the app to use the lower-level features of SurfaceFlinger."
	obj.Info_es = "Permite que la aplicación use las funciones de nivel inferior de SurfaceFlinger."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.READ_FRAME_BUFFER"
	obj.Description_pt_br = "leia o buffer do quadro"
	obj.Description_en = "read frame buffer"
	obj.Description_es = "leer el búfer de trama"
	obj.Info_pt_br = "Permite que o aplicativo leia o conteúdo do buffer de quadros."
	obj.Info_en = "Allows the app to read the frame buffer content."
	obj.Info_es = "Permite que la aplicación lea el contenido del búfer de trama."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.BRICK"
	obj.Description_pt_br = "desativar permanentemente o telefone"
	obj.Description_en = "permanently disable the phone"
	obj.Description_es = "deshabilitar permanentemente el teléfono"
	obj.Info_pt_br = "Permite a aplicação remover todo o telefone permanentemente. Isso é muito perigoso."
	obj.Info_en = "Allows the app to remove the entire phone permanently. That is very dangerous."
	obj.Info_es = "Permite que la aplicación elimine todo el teléfono de forma permanente. Esto es muy peligroso"
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.REBOOT"
	obj.Description_pt_br = "forçar reinicialização do telefone"
	obj.Description_en = "force phone restart"
	obj.Description_es = "forzar reinicio del teléfono"
	obj.Info_pt_br = "Permite uma aplicação de telefone ou reiniciar."
	obj.Info_en = "Allow a phone application or restart."
	obj.Info_es = "Permitir una aplicación de teléfono o reiniciar."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.DEVICE_POWER"
	obj.Description_pt_br = "liga ou desliga o telefone"
	obj.Description_en = "turns the phone on or off"
	obj.Description_es = "enciende o apaga el teléfono"
	obj.Info_pt_br = "Permite a aplicação ligar ou desligar o telefone."
	obj.Info_en = "Allows the app to turn the phone on or off."
	obj.Info_es = "Permite que la aplicación encienda o apague el teléfono."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.FACTORY_TEST"
	obj.Description_pt_br = "executar no modo de teste de fábrica"
	obj.Description_en = "run in factory test mode"
	obj.Description_es = "ejecutar en modo de prueba de fábrica"
	obj.Info_pt_br = "Executar como um teste de nível baixo do fabricante, permitir acesso completo ao hardware do telefone. Disponível apenas quando um telefone estiver sendo executado no modo de teste do fabricante."
	obj.Info_en = "Realice una prueba de bajo nivel del fabricante, permita el acceso completo al hardware del teléfono. Disponible solo cuando un teléfono se ejecuta en el modo de prueba del fabricante."
	obj.Info_es = "Realice una prueba de bajo nivel del fabricante, permita el acceso completo al hardware del teléfono. Disponible solo cuando un teléfono se ejecuta en el modo de prueba del fabricante."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.BROADCAST_PACKAGE_REMOVED"
	obj.Description_pt_br = "enviar transmissão removida do pacote"
	obj.Description_en = "send stream removed from package"
	obj.Description_es = "enviar flujo eliminado del paquete"
	obj.Info_pt_br = "Permite a aplicação transmitir uma notificação de que um pacote de aplicativos foi removido. Os aplicativos maliciosas podem usar isso para eliminar qualquer outro aplicativo em execução."
	obj.Info_en = "Allows the app to transmit a notification that an app package has been removed. Malicious applications can use this to eliminate any other running applications."
	obj.Info_es = "Permite que la aplicación transmita una notificación de que se ha eliminado un paquete de la aplicación. Las aplicaciones maliciosas pueden usar esto para eliminar cualquier otra aplicación en ejecución."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.BROADCAST_SMS"
	obj.Description_pt_br = "enviar transmissão recebida por SMS"
	obj.Description_en = "send incoming SMS transmission"
	obj.Description_es = "enviar transmisión entrante de SMS"
	obj.Info_pt_br = "Permite a aplicação transmitir uma notificação de que uma mensagem SMS foi recebida. Os aplicativos maliciosos podem usar isso para forjar mensagens SMS recebidas."
	obj.Info_en = "Allows the app to transmit a notification that an SMS message has been received. Malicious applications can use this to forge incoming SMS messages."
	obj.Info_es = "Permite que la aplicación transmita una notificación de que se ha recibido un mensaje SMS. Las aplicaciones malintencionadas pueden usar esto para falsificar mensajes SMS entrantes."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.BROADCAST_WAP_PUSH"
	obj.Description_pt_br = "envia transmissão recebida por WAP-PUSH"
	obj.Description_en = "send transmission received by WAP-PUSH"
	obj.Description_es = "enviar transmisión recibida por WAP-PUSH"
	obj.Info_pt_br = "Permite a aplicação transmitir uma notificação de que uma mensagem WAP-PUSH foi recebida. As aplicações maliciosas podem usar isso para forjar o recebimento de mensagens MMS ou substituir o conteúdo de qualquer página da Web silenciosamente por variantes maliciosas."
	obj.Info_en = "Allows the app to transmit a notification that a WAP-PUSH message has been received. Malicious applications can use this to forge the receipt of MMS messages or to silently replace the content of any web page with malicious variants."
	obj.Info_es = "Permite que la aplicación transmita una notificación de que se ha recibido un mensaje WAP-PUSH. Las aplicaciones maliciosas pueden usar esto para falsificar la recepción de mensajes MMS o para reemplazar silenciosamente el contenido de cualquier página web con variantes maliciosas."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.MASTER_CLEAR"
	obj.Description_pt_br = "redefinir o sistema para os padrões de fábrica"
	obj.Description_en = "reset the system to factory defaults"
	obj.Description_es = "restablecer el sistema a los valores predeterminados de fábrica"
	obj.Info_pt_br = "Permite a aplicação redefinir completamente o sistema para as configurações de fábrica, apagando todos os dados, configurações e aplicativos instalados."
	obj.Info_en = "Allows the app to completely reset the system to factory settings, erasing all installed data, settings and applications."
	obj.Info_es = "Permite que la aplicación restablezca completamente el sistema a la configuración de fábrica, borrando todos los datos, configuraciones y aplicaciones instaladas."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.CALL_PRIVILEGED"
	obj.Description_pt_br = "ligue diretamente para qualquer número de telefone"
	obj.Description_en = "call directly to any phone number"
	obj.Description_es = "llame directamente a cualquier número de teléfono"
	obj.Info_pt_br = "Permite a aplicação qualquer número de telefone, incluindo números de emergência, sem a sua intervenção. Aplicações maliciosas podem fazer chamadas desnecessárias e ilegais para serviços de emergência."
	obj.Info_en = "Allows the application of any phone number, including emergency numbers, without your intervention. Malicious applications can make unnecessary and illegal calls to emergency services."
	obj.Info_es = "Permite la aplicación de cualquier número de teléfono, incluidos los números de emergencia, sin su intervención. Las aplicaciones maliciosas pueden hacer llamadas innecesarias e ilegales a los servicios de emergencia."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.PERFORM_CDMA_PROVISIONING"
	obj.Description_pt_br = "inicia diretamente a configuração do telefone CDMA"
	obj.Description_en = "directly initiates CDMA phone setup"
	obj.Description_es = "inicia directamente la configuración del teléfono CDMA"
	obj.Info_pt_br = "Permite a aplicação iniciar o provisionamento de CDMA. Os aplicativos maliciosos podem iniciar o provisionamento de CDMA desnecessariamente"
	obj.Info_en = "Allows the application to start provisioning CDMA. Malicious applications may unnecessarily initiate CDMA provisioning"
	obj.Info_es = "Permite que la aplicación comience a aprovisionar CDMA. Las aplicaciones malintencionadas pueden iniciar innecesariamente el aprovisionamiento de CDMA"
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.CONTROL_LOCATION_UPDATES"
	obj.Description_pt_br = "controlar notificações de atualização de local"
	obj.Description_en = "control location update notifications"
	obj.Description_es = "controlar las notificaciones de actualización de ubicación"
	obj.Info_pt_br = "Permite ativar / desativar notificações de atualização de localização do rádio. Não é para ser usado com aplicações comuns."
	obj.Info_en = "Enables / disables radio location update notifications. It is not to be used with common applications."
	obj.Info_es = "Activa / desactiva las notificaciones de actualización de ubicación de radio. No se debe utilizar con aplicaciones comunes."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.ACCESS_CHECKIN_PROPERTIES"
	obj.Description_pt_br = "acessar propriedades de check-in"
	obj.Description_en = "access check-in properties"
	obj.Description_es = "acceder a las propiedades de check-in"
	obj.Info_pt_br = "Permite acesso de leitura / gravação às propriedades carregadas pelo serviço de check-in. Não é para ser usado com aplicações comuns."
	obj.Info_en = "Allows read / write access to properties loaded by the check-in service. It is not to be used with common applications."
	obj.Info_es = "Permite el acceso de lectura / escritura a las propiedades cargadas por el servicio de registro. No se debe utilizar con aplicaciones comunes."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.PACKAGE_USAGE_STATS"
	obj.Description_pt_br = "atualizar estatísticas de uso do componente"
	obj.Description_en = "update component usage statistics"
	obj.Description_es = "actualizar las estadísticas de uso de componentes"
	obj.Info_pt_br = "Permite a modificação das estatísticas de uso de componentes coletados. Não é para ser usado com aplicativos comuns."
	obj.Info_en = "It allows the modification of the usage statistics of collected components. It is not to be used with common applications."
	obj.Info_es = "Permite la modificación de las estadísticas de uso de los componentes recopilados. No se debe utilizar con aplicaciones comunes."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.BATTERY_STATS"
	obj.Description_pt_br = "modificar estatísticas da bateria"
	obj.Description_en = "modify battery statistics"
	obj.Description_es = "modificar las estadísticas de la batería"
	obj.Info_pt_br = "Permite a modificação das estatísticas coletadas da bateria. Não é para ser usado com aplicativos comuns."
	obj.Info_en = "It allows the modification of the statistics collected from the battery. It is not to be used with common applications."
	obj.Info_es = "Permite la modificación de las estadísticas recopiladas de la batería. No se debe utilizar con aplicaciones comunes."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.BACKUP"
	obj.Description_pt_br = "backup e restauração do sistema de controle"
	obj.Description_en = "backup and restore control system"
	obj.Description_es = "sistema de control de respaldo y restauración"
	obj.Info_pt_br = "Permite a aplicação controle do mecanismo de backup e restauração do sistema. Não é para ser usado com aplicativos comuns."
	obj.Info_en = "Allows the application to control the system's backup and restore mechanism. It is not to be used with common applications."
	obj.Info_es = "Permite que la aplicación controle el mecanismo de respaldo y restauración del sistema. No se debe utilizar con aplicaciones comunes."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.BIND_APPWIDGET"
	obj.Description_pt_br = "escolha widgets"
	obj.Description_en = "choose widgets"
	obj.Description_es = "elegir widgets"
	obj.Info_pt_br = "Permite a aplicação informar ao sistema quais widgets podem ser usados ​​por qual aplicativo. Com essa permissão, os aplicativos podem acessar dados pessoais para outros aplicativos. Não é para ser usado com aplicativos comuns."
	obj.Info_en = "Allows the app to tell the system which widgets can be used by which app. With this permission, applications can access personal data for other applications. It is not to be used with common applications."
	obj.Info_es = "Permite que la aplicación le diga al sistema qué widgets puede usar cada aplicación. Con este permiso, las aplicaciones pueden acceder a datos personales para otras aplicaciones. No se debe utilizar con aplicaciones comunes."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.CHANGE_BACKGROUND_DATA_SETTING"
	obj.Description_pt_br = "altere a configuração de uso de dados em segundo plano"
	obj.Description_en = "change the background data usage setting"
	obj.Description_es = "cambiar la configuración de uso de datos de fondo"
	obj.Info_pt_br = "Permite a aplicação alterar a configuração de uso de dados em segundo plano."
	obj.Info_en = "Allows the app to change the data usage setting in the background."
	obj.Info_es = "Permite que la aplicación cambie la configuración de uso de datos en segundo plano."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.GLOBAL_SEARCH"
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.GLOBAL_SEARCH_CONTROL"
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.SET_WALLPAPER_COMPONENT"
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.ACCESS_CACHE_FILESYSTEM"
	obj.Description_pt_br = "acesse o sistema de arquivos em cache"
	obj.Description_en = "access the cached file system"
	obj.Description_es = "acceder al sistema de archivos en caché"
	obj.Info_pt_br = "Permite a aplicação leitura e gravação no sistema de arquivos em cache."
	obj.Info_en = "Allows the application to read and write to the cached file system."
	obj.Info_es = "Permite que la aplicación lea y escriba en el sistema de archivos en caché."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.COPY_PROTECTED_DATA"
	obj.Description_pt_br = "Permite chamar o serviço de contêiner padrão para copiar o conteúdo. Não é para ser usado com aplicativos comuns."
	obj.Description_en = "Allows you to call the standard container service to copy the content. It is not to be used with common applications."
	obj.Description_es = "Le permite llamar al servicio de contenedor estándar para copiar el contenido. No se debe utilizar con aplicaciones comunes."
	obj.Info_pt_br = "Permite chamar o serviço de contêiner padrão para copiar o conteúdo. Não é para ser usado com aplicativos comuns."
	obj.Info_en = "Allows you to call the standard container service to copy the content. It is not to be used with common applications."
	obj.Info_es = "Le permite llamar al servicio de contenedor estándar para copiar el contenido. No se debe utilizar con aplicaciones comunes."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.C2D_MESSAGE"
	obj.Description_pt_br = "Permite que a nuvem envie mensagens para o dispositivo"
	obj.Description_en = "Allows the cloud to send messages to the device"
	obj.Description_es = "Permite que la nube envíe mensajes al dispositivo"
	obj.Info_pt_br = "Permite a aplicação receber notificações push."
	obj.Info_en = "Allows the app to receive push notifications."
	obj.Info_es = "Permite que la aplicación reciba notificaciones push."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.ADD_VOICEMAIL"
	obj.Description_pt_br = "Adicione mensagens de voz ao sistema"
	obj.Description_en = "Add voice messages to the system"
	obj.Description_es = "Agregar mensajes de voz al sistema"
	obj.Info_pt_br = "Permite a aplicação adicionar mensagens de voz ao sistema."
	obj.Info_en = "Allows the app to add voice messages to the system."
	obj.Info_es = "Permite que la aplicación agregue mensajes de voz al sistema."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.ACCEPT_HANDOVER"
	obj.Info_pt_br = "Permite que o aplicativo de chamada continue uma chamada iniciada em outro aplicativo. Um exemplo é um aplicativo de videochamada que deseja continuar uma chamada de voz na rede móvel do usuário."
	obj.Info_en = "Allows the calling application to continue a call initiated in another application. An example is a video call application that wants to continue a voice call on the user's mobile network."
	obj.Info_es = "Permite que la aplicación que realiza la llamada continúe una llamada iniciada en otra aplicación. Un ejemplo es una aplicación de videollamada que desea continuar una llamada de voz en la red móvil del usuario."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.ACCESS_NOTIFICATION_POLICY"
	obj.Info_pt_br = "Permissão do marcador para aplicativos que desejam acessar a política de notificação."
	obj.Info_en = "Bookmark permission for apps that want to access the notification policy."
	obj.Info_es = "Marcar permiso para aplicaciones que desean acceder a la política de notificación."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.ANSWER_PHONE_CALLS"
	obj.Info_pt_br = "Permite uma aplicação de resposta a ligações."
	obj.Info_en = "Allows an application to answer calls."
	obj.Info_es = "Permite que una aplicación responda llamadas."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.BIND_ACCESSIBILITY_SERVICE"
	obj.Info_pt_br = "Deve ser exigido por um AccessibilityService, para garantir que apenas o sistema possa se vincular a ele."
	obj.Info_en = "It must be required by an AccessibilityService, to ensure that only the system can link to it."
	obj.Info_es = "Debe ser requerido por un AccessibilityService para garantizar que solo el sistema pueda vincularse a él."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.BIND_AUTOFILL_SERVICE"
	obj.Info_pt_br = "Deve ser exigido por um AutofillService, para garantir que apenas o sistema possa se vincular a ele."
	obj.Info_en = "It must be required by an AutofillService, to ensure that only the system can be linked to it."
	obj.Info_es = "Debe ser requerido por un AutofillService, para garantizar que solo el sistema pueda vincularse a él."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.BIND_CARRIER_MESSAGING_SERVICE"
	obj.Info_pt_br = "O processo do sistema que é permitido vincular aos serviços nos aplicativos da operadora terá essa permissão."
	obj.Info_en = "The system process that is allowed to link to services in the operator's applications will have this permission."
	obj.Info_es = "El proceso del sistema que se permite vincular a los servicios en las aplicaciones del operador tendrá este permiso."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.BIND_CARRIER_SERVICES"
	obj.Info_pt_br = "O processo do sistema que pode se vincular aos serviços nos aplicativos da operadora terá essa permissão. Os aplicativos da operadora devem usar essa permissão para proteger seus serviços aos quais somente o sistema está autorizado."
	obj.Info_en = "The system process that can link to services in the operator's applications will have this permission. Operator applications must use this permission to protect their services to which only the system is authorized."
	obj.Info_es = "El proceso del sistema que puede vincularse a los servicios en las aplicaciones del operador tendrá este permiso. Las aplicaciones del operador deben usar este permiso para proteger sus servicios para los cuales solo el sistema está autorizado."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.BIND_CHOOSER_TARGET_SERVICE"
	obj.Info_pt_br = "Deve ser exigido por um ChooserTargetService, para garantir que apenas o sistema possa se vincular a ele"
	obj.Info_en = "Must be required by a ChooserTargetService, to ensure that only the system can link to it"
	obj.Info_es = "Debe ser requerido por un ChooserTargetService, para garantizar que solo el sistema pueda vincularse a él"
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.BIND_CONDITION_PROVIDER_SERVICE"
	obj.Info_pt_br = "Deve ser exigido por um ConditionProviderService, para garantir que apenas o sistema possa se vincular a ele"
	obj.Info_en = "Must be required by a ConditionProviderService, to ensure that only the system can link to it"
	obj.Info_es = "Debe ser requerido por un ConditionProviderService, para garantizar que solo el sistema pueda vincularse a él"
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.BIND_DREAM_SERVICE"
	obj.Info_pt_br = "Deve ser exigido por um DreamService, para garantir que apenas o sistema possa se vincular a ele."
	obj.Info_en = "It must be required by a DreamService, to ensure that only the system can link to it."
	obj.Info_es = "Debe ser requerido por un DreamService, para garantizar que solo el sistema pueda vincularse a él."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.BIND_INCALL_SERVICE"
	obj.Info_pt_br = "Deve ser exigido por um InCallService, para garantir que apenas o sistema possa se vincular a ele."
	obj.Info_en = "It must be required by an InCallService, to ensure that only the system can link to it."
	obj.Info_es = "Debe ser requerido por un InCallService, para garantizar que solo el sistema pueda vincularse a él."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.BIND_MIDI_DEVICE_SERVICE"
	obj.Info_pt_br = "Deve ser exigido por um MidiDeviceService, para garantir que apenas o sistema possa se vincular a ele."
	obj.Info_en = "It must be required by a MidiDeviceService, to ensure that only the system can be linked to it."
	obj.Info_es = "Debe ser requerido por un MidiDeviceService, para garantizar que solo el sistema pueda vincularse a él."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.BIND_NFC_SERVICE"
	obj.Info_pt_br = "Deve ser exigido por um HostApduService ou OffHostApduService para garantir que apenas o sistema possa se vincular a ele."
	obj.Info_en = "It must be required by a HostApduService or OffHostApduService to ensure that only the system can link to it."
	obj.Info_es = "Debe ser requerido por un HostApduService o OffHostApduService para garantizar que solo el sistema pueda conectarse a él."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
	obj.Info_pt_br = "Deve ser exigido por um NotificationListenerService, para garantir que apenas o sistema possa se vincular a ele."
	obj.Info_en = "It must be required by a NotificationListenerService, to ensure that only the system can link to it."
	obj.Info_es = "Debe ser requerido por un NotificationListenerService, para garantizar que solo el sistema pueda vincularse a él."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.BIND_PRINT_SERVICE"
	obj.Info_pt_br = "Deve ser exigido por um PrintService, para garantir que apenas o sistema possa se vincular a ele."
	obj.Info_en = "It must be required by a PrintService, to ensure that only the system can be linked to it."
	obj.Info_es = "Debe ser requerido por un PrintService, para garantizar que solo el sistema pueda vincularse a él."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.BIND_QUICK_SETTINGS_TILE"
	obj.Info_pt_br = "Permite uma aplicação de ligação a blocos de configurações rápidas de terceiros."
	obj.Info_en = "Allows a connection application to third party quick setting blocks."
	obj.Info_es = "Permite una aplicación de conexión a bloques de configuración rápida de terceros."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.BIND_REMOTEVIEWS"
	obj.Info_pt_br = "Deve ser exigido por um RemoteViewsService, para garantir que apenas o sistema possa se vincular a ele."
	obj.Info_en = "It must be required by a RemoteViewsService, to ensure that only the system can link to it."
	obj.Info_es = "Debe ser requerido por un RemoteViewsService, para garantizar que solo el sistema pueda vincularse a él."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.BIND_SCREENING_SERVICE"
	obj.Info_pt_br = "Deve ser exigido por um CallScreeningService, para garantir que apenas o sistema possa se vincular a ele."
	obj.Info_en = "It must be required by a CallScreeningService, to ensure that only the system can be linked to it."
	obj.Info_es = "Debe ser requerido por un CallScreeningService, para garantizar que solo el sistema pueda vincularse a él."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.BIND_TELECOM_CONNECTION_SERVICE"
	obj.Info_pt_br = "Deve ser exigido por um ConnectionService, para garantir que apenas o sistema possa se vincular a ele."
	obj.Info_en = "It must be required by a ConnectionService, to ensure that only the system can link to it."
	obj.Info_es = "Debe ser requerido por un ConnectionService, para garantizar que solo el sistema pueda conectarse a él."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.BIND_TEXT_SERVICE"
	obj.Info_pt_br = "Deve ser exigido por um TextService (por exemplo, SpellCheckerService) para garantir que apenas o sistema possa se vincular a ele."
	obj.Info_en = "It must be required by a TextService (for example, SpellCheckerService) to ensure that only the system can link to it."
	obj.Info_es = "Debe ser requerido por un TextService (por ejemplo, SpellCheckerService) para garantizar que solo el sistema pueda vincularse a él."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.BIND_TV_INPUT"
	obj.Info_pt_br = "Deve ser exigido por um TvInputService para garantir que apenas o sistema possa se vincular a ele."
	obj.Info_en = "It must be required by a TvInputService to ensure that only the system can link to it."
	obj.Info_es = "Debe ser requerido por un TvInputService para garantizar que solo el sistema pueda vincularse a él."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.BIND_VISUAL_VOICEMAIL_SERVICE"
	obj.Info_pt_br = "Deve ser exigido por um link"
	obj.Info_en = "Must be required by a link"
	obj.Info_es = "Debe ser requerido por un enlace"
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.BIND_VOICE_INTERACTION"
	obj.Info_pt_br = "Deve ser exigido por um VoiceInteractionService, para garantir que apenas o sistema possa se vincular a ele."
	obj.Info_en = "It must be required by a VoiceInteractionService, to ensure that only the system can be linked to it."
	obj.Info_es = "Debe ser requerido por un VoiceInteractionService, para garantizar que solo el sistema pueda vincularse a él."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.BIND_VPN_SERVICE"
	obj.Info_pt_br = "Deve ser exigido por um VpnService, para garantir que apenas o sistema possa se vincular a ele."
	obj.Info_en = "It must be required by a VpnService, to ensure that only the system can be linked to it."
	obj.Info_es = "Debe ser requerido por un VpnService, para garantizar que solo el sistema pueda vincularse a él."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.BIND_VR_LISTENER_SERVICE"
	obj.Info_pt_br = "Deve ser exigido por um VrListenerService, para garantir que apenas o sistema possa se vincular a ele."
	obj.Info_en = "It must be required by a VrListenerService, to ensure that only the system can link to it."
	obj.Info_es = "Debe ser requerido por un VrListenerService, para garantizar que solo el sistema pueda vincularse a él."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.BLUETOOTH_PRIVILEGED"
	obj.Info_pt_br = "Permite que os aplicativos emparelhem dispositivos bluetooth sem a interação do usuário e permita ou não o acesso à agenda telefônica ou ao acesso a mensagens. Isso não está disponível para aplicativos de terceiros."
	obj.Info_en = "Allows applications to pair Bluetooth devices without user interaction and allows or disallows access to the phonebook or access to messages. This is not available for third party applications."
	obj.Info_es = "Permite que las aplicaciones emparejen dispositivos Bluetooth sin interacción del usuario y permite o impide el acceso a la agenda telefónica o el acceso a los mensajes. Esto no está disponible para aplicaciones de terceros."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.BODY_SENSORS"
	obj.Info_pt_br = "Permite a aplicação acesso a dados de sensores que o usuário utiliza para medir o que está acontecendo dentro de seu corpo, como freqüência cardíaca."
	obj.Info_en = "It allows the application to access sensor data that the user uses to measure what is happening inside his body, such as heart rate."
	obj.Info_es = "Permite que la aplicación acceda a los datos del sensor que el usuario usa para medir lo que sucede dentro de su cuerpo, como la frecuencia cardíaca."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.CAPTURE_AUDIO_OUTPUT"
	obj.Info_pt_br = "Permite uma aplicação de captura de saída de áudio."
	obj.Info_en = "Enables an audio output capture application."
	obj.Info_es = "Habilita una aplicación de captura de salida de audio."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.CAPTURE_SECURE_VIDEO_OUTPUT"
	obj.Info_pt_br = "Permite uma aplicação de captura de saída de vídeo segura."
	obj.Info_en = "Enables a secure video output capture application."
	obj.Info_es = "Permite una aplicación segura de captura de salida de video."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.CAPTURE_VIDEO_OUTPUT"
	obj.Info_pt_br = "Permite uma aplicação de captura de saída de vídeo."
	obj.Info_en = "It allows a video output capture application."
	obj.Info_es = "Permite una aplicación de captura de salida de video."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.FOREGROUND_SERVICE"
	obj.Info_pt_br = "Permite que o aplicativo comum use."
	obj.Info_en = "Allows the common application to use."
	obj.Info_es = "Permite el uso de la aplicación común."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.GET_ACCOUNTS_PRIVILEGED"
	obj.Info_pt_br = "Permite acesso à lista de contas no Serviço de Contas."
	obj.Info_en = "Allows access to the list of accounts in the Account Service."
	obj.Info_es = "Permite el acceso a la lista de cuentas en el Servicio de cuenta."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.INSTALL_SHORTCUT"
	obj.Info_pt_br = "Permite a aplicação instalar um atalho no Launcher."
	obj.Info_en = "Allows the app to install a shortcut on the Launcher."
	obj.Info_es = "Permite que la aplicación instale un acceso directo en el Iniciador."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.INSTANT_APP_FOREGROUND_SERVICE"
	obj.Info_pt_br = "Permite que o aplicativo instantâneo crie serviços em primeiro plano."
	obj.Info_en = "Allows the instant application to create services in the foreground."
	obj.Info_es = "Permite que la aplicación instantánea cree servicios en primer plano."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.LOCATION_HARDWARE"
	obj.Info_pt_br = "Permite a aplicação usar recursos de localização em hardware, como a API de geofencing."
	obj.Info_en = "Allows the app to use hardware localization features, such as the geofencing API."
	obj.Info_es = "Permite que la aplicación use funciones de localización de hardware, como la API de geofencing."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.MANAGE_DOCUMENTS"
	obj.Info_pt_br = "Permite a aplicação gerenciar o acesso a documentos, geralmente como parte de um seletor de documentos."
	obj.Info_en = "Allows the app to manage access to documents, usually as part of a document selector."
	obj.Info_es = "Permite que la aplicación administre el acceso a los documentos, generalmente como parte de un selector de documentos."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.MANAGE_OWN_CALLS"
	obj.Info_pt_br = "Permite a um aplicativo de chamada que gerencia suas próprias chamadas através do autogerenciamento."
	obj.Info_en = "Allows a calling application to manage its own calls through self-management."
	obj.Info_es = "Permite que una aplicación de llamadas administre sus propias llamadas a través de la autogestión."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.MEDIA_CONTENT_CONTROL"
	obj.Info_pt_br = "Permite a aplicação saber qual conteúdo está sendo reproduzido e controlar sua reprodução."
	obj.Info_en = "It allows the application to know what content is being played and to control its reproduction."
	obj.Info_es = "Le permite a la aplicación saber qué contenido se está reproduciendo y controlar su reproducción."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.NFC_TRANSACTION_EVENT"
	obj.Info_pt_br = "Permite que os aplicativos recebam eventos de transação NFC."
	obj.Info_en = "Allows applications to receive NFC transaction events."
	obj.Info_es = "Permite que las aplicaciones reciban eventos de transacciones NFC."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.READ_CALL_LOG"
	obj.Info_pt_br = "Permite a aplicação ler o registro de chamadas do usuário."
	obj.Info_en = "Allows the app to read the user's call log."
	obj.Info_es = "Permite que la aplicación lea el registro de llamadas del usuario."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.READ_PHONE_NUMBERS"
	obj.Info_pt_br = "Permite acesso de leitura aos números de telefone do dispositivo. Esse é um subconjunto dos recursos concedidos por"
	obj.Info_en = "Allows read access to the device's phone numbers. This is a subset of the resources provided by"
	obj.Info_es = "Permite el acceso de lectura a los números de teléfono del dispositivo. Este es un subconjunto de los recursos proporcionados por"
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.READ_VOICEMAIL"
	obj.Info_pt_br = "Permite a aplicação leitura de mensagens de voz no sistema."
	obj.Info_en = "Allows the application to read voice messages in the system."
	obj.Info_es = "Permite que la aplicación lea mensajes de voz en el sistema."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.REQUEST_COMPANION_RUN_IN_BACKGROUND"
	obj.Info_pt_br = "Permite uma aplicação 'Companheira' de rodar no segundo plano."
	obj.Info_en = "Allows a 'Companion' application to run in the background."
	obj.Info_es = "Permite que una aplicación 'Companion' se ejecute en segundo plano."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.REQUEST_COMPANION_USE_DATA_IN_BACKGROUND"
	obj.Info_pt_br = "Permite uma aplicação 'Companheira' de usar dados no segundo plano."
	obj.Info_en = "Allows a 'Companion' application to use data in the background."
	obj.Info_es = "Permite que una aplicación 'Companion' use datos en segundo plano."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.REQUEST_DELETE_PACKAGES"
	obj.Info_pt_br = "Permite uma aplicação de solicitação de exclusão de pacotes. Aplicativos direcionados a APIs."
	obj.Info_en = "It allows a request to exclude packages. API-driven applications."
	obj.Info_es = "Permite una solicitud para excluir paquetes. Aplicaciones basadas en API."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"
	obj.Info_pt_br = "Permissão que um aplicativo deve manter para poder usar."
	obj.Info_en = "Permission that an application must maintain in order to use."
	obj.Info_es = "Permiso que una aplicación debe mantener para poder usar."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.SEND_RESPOND_VIA_MESSAGE"
	obj.Info_pt_br = "Permite que o aplicativo (Telefone) envie uma solicitação a outros aplicativos para lidar com a ação de resposta por mensagem durante as chamadas recebidas."
	obj.Info_en = "Allows the app (Phone) to send a request to other apps to handle the message reply action during incoming calls."
	obj.Info_es = "Permite que la aplicación (Teléfono) envíe una solicitud a otras aplicaciones para manejar la acción de respuesta del mensaje durante las llamadas entrantes."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.TRANSMIT_IR"
	obj.Info_pt_br = "Permite usar o transmissor IR do dispositivo, se disponível."
	obj.Info_en = "Allows you to use the device's IR transmitter, if available."
	obj.Info_es = "Le permite usar el transmisor IR del dispositivo, si está disponible."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.UNINSTALL_SHORTCUT"
	obj.Info_pt_br = "Não use essa permissão no seu aplicativo. Esta permissão não é mais suportada."
	obj.Info_en = "Do not use this permission in your application. This permission is no longer supported."
	obj.Info_es = "No use este permiso en su aplicación. Este permiso ya no es compatible."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.USE_BIOMETRIC"
	obj.Info_pt_br = "Permite que o aplicativo use modalidades biométricas compatíveis com o dispositivo."
	obj.Info_en = "Allows the app to use biometric modalities compatible with the device."
	obj.Info_es = "Permite que la aplicación use modalidades biométricas compatibles con el dispositivo."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.USE_FINGERPRINT"
	obj.Info_pt_br = "Essa constante foi descontinuada na API nível 28. Os aplicativos devem requerer USE_BIOMETRIC no lugar."
	obj.Info_en = "This constant has been deprecated at API level 28. Applications must require USE_BIOMETRIC instead."
	obj.Info_es = "Esta constante ha quedado en desuso en el nivel 28 de la API. Las aplicaciones deben requerir USE_BIOMETRIC en su lugar."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.WRITE_CALL_LOG"
	obj.Info_pt_br = "Permite uma aplicação de gravação (mas não leitura) dos dados do log de chamadas do usuário."
	obj.Info_en = "Allows an application to write (but not read) the user's call log data."
	obj.Info_es = "Permite que una aplicación escriba (pero no lea) los datos del registro de llamadas del usuario."
	all = append(all, obj)

	obj = reports.ManifestPermission{}
	obj.Title = "android.permission.WRITE_VOICEMAIL"
	obj.Info_pt_br = "Permite a aplicação modificação e remoção de erros de voz existentes no sistema."
	obj.Info_en = "It allows the application to modify and remove existing voice errors in the system."
	obj.Info_es = "Permite que la aplicación modifique y elimine los errores de voz existentes en el sistema."
	all = append(all, obj)


	return all
}
