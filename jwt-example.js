const express = require("express");
const bcrypt = require('bcrypt');

//Boilerplate dependencies for Auth0
const jwt = require('express-jwt');
const jwks = require('jwks-rsa');
const cors = require('cors'); 
var request = require("request");

//read environment variables
require('dotenv').config('.env');

const {User, Item} = require('./models');

// initialise Express
const app = express();

//allow cross-origin resource sharing
app.use(cors());

// specify out request bodies are json
app.use(express.json());

//JWT Boilerplate
const checkJwt = jwt({
secret: jwks.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `https://${process.env.AUTH0_DOMAIN}.well-known/jwks.json`
}),
audience: process.env.AUTH0_AUDIENCE,
issuer: `https://${process.env.AUTH0_DOMAIN}`,
algorithms: ['RS256']
});

//requires no auth
app.get('/', (req, res) => {
  res.send('<h1>Hello!!!!</h1>')
})

// post users requires no auth
app.post('/users', async(req,res) =>{
  bcrypt.hash(req.body.password,saltRounds, async function(err,hash){
    let newUser = await User.create({'name':req.body.name, 'password':hash});
    res.json({newUser})
  })
});

// user and item endpoints portected by JWT

// I want to get all user
app.get('/users', checkJwt, async (req, res) => {
  //what should i put here?
  let users = await User.findAll()
  res.json({users});
})

// I want to get one users
app.get('/users/:id', checkJwt, async (req, res) => {
  let user = await User.findByPk(req.params.id);
  res.json({user});
})

// I want to get all items
app.get('/items', checkJwt, async(req, res)=> {
  let items = await Item.findAll();
  res.json({items});
})

// I want to get one item
app.get('/items/:id', checkJwt, async(req, res)=> {
  let item = await Item.findByPk(req.params.id);
  res.json({item});
})

// I want to delete one item
app.delete('/items/:id', checkJwt, async(req, res)=> {
  await Item.destroy({where: {id: req.params.id}});
  res.send('Deleted!')
})

// I want to create one item
app.post('/items', checkJwt, async(req, res)=> {
  let newItem = await Item.create(req.body);
  res.json({newItem})
})

// I want to update one item
app.put('/items/:id', checkJwt, async(req, res)=> {
  let updatedItem = await Item.update(req.body, {
    where : {id : req.params.id}
  });
  res.json({updatedItem})
})

// configure basicAuth
app.use(basicAuth({
  authorizer : dbAuthorizer,
  authorizeAsync : true,
  unauthorizedResponse : () => "You do not have access to this content"
}))

// getting a new JWT requires basic auth
//get missing info from you auth0 dashboard and secure in an env file
app.get('/tokens', async(req,res) =>{
  const options = { method: 'POST',
    url: `${process.env.AUTH0_URL}`,
    headers: { 'content-type': 'application/json' },
    body: `{"client_id":${process.env.CLIENT_ID},"client_secret":${process.env.CLIENT_SECRET},"audience":${process.env.AUDIENCE},"grant_type":"client_credentials"}`
  };

  request(options, function (error, response, body) {
    if (error) throw new Error(error);
    const jsonBody = JSON.parse(body)
    const token = jsonBody.access_token
    console.log("New JWT sent to authenticated user")
    res.json(token)
  });
})

app.listen(8000, () => {
  console.log("Server running on port 8000");
});