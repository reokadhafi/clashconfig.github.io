function parserv2ray(){

  var data_vmess = document.getElementById("akun").value

  a = data_vmess.replace("vmess://","")

  b = atob(a)

  c = JSON.parse(b)

  //d = JSON.stringify(b)

  console.log(b)

  var log = document.getElementById("boxlog")

  log.innerHTML = b

  return c

}
