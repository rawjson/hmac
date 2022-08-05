/* 

An encryption mechanism that creates a hash using JSON payload
HMAC is only for hashing a string or an object and it can not
decrypt the message. To encrypt or decrypt use Cipher

*/

const express = require('express');
const { createHmac } = require('node:crypto');
const hmacVerify = require('./middlewares/hmacVerify.js');
const fs = require('fs');
const path = require('path');

require('dotenv').config();

const app = express();
const port = 8080;

app.use(express.json());

app.post('/hash', (req, res) => {
  const { body } = req;
  if (typeof body !== 'object') {
    //
    // ---> Since we are using json objects
    //      an object is required to create a hash

    res.status(400).json({
      message: `An object with secret key/value pairs is needed to generate a hash`,
    });
  } else {
    //
    // create a hash that encloses any secret info
    //

    const hash = createHmac('sha256', process.env.SECRET)
      .update(JSON.stringify(body.password))
      .digest('base64');

    //  ---> our api consumers share a password and we store it in memory with a hash
    try {
      fs.writeFileSync(
        path.resolve(__dirname, `./data.json`),
        JSON.stringify({ hash })
      );
    } catch (err) {
      console.log(err);
    }

    res.status(201).json({
      message: 'Include your password as "api-key" in request headers',
    });
  }
});

//  the purpose of this verification is to find out if the request is
//  coming from a valid api consumer that we trust
//  we stored the password as hash so even if the hash value gets
//  compromised, the attacker won't be able to guess the password

app.get('/protected', hmacVerify(fs, path), (req, res) => {
  res.json({ message: 'Your are now visting a protected route' });
});

app.listen(port, () => {
  console.log(`----> Serving listening on localhost:${port}`);
});
