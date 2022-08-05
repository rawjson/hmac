const { createHmac, timingSafeEqual } = require('node:crypto');

const hmacVerify = (fs, path) => {
  return (req, res, next) => {
    try {
      //
      // read the hash that we stored earlier in a json file
      const file = fs.readFileSync(
        path.resolve(__dirname, '../data.json'),
        'utf-8'
      );

      // ----> here we generate a hash using our secret key
      //       by reading the password of user in the headers

      const generatedHash = createHmac('sha256', process.env.SECRET)
        .update(JSON.stringify(req.headers['api-key']), 'utf-8')
        .digest('base64');

      if (
        // ----> compares without leaking timing info
        //  -    could allow an attacker to guess one of
        //  -    the values otherwise

        timingSafeEqual(
          Buffer.from(generatedHash),
          Buffer.from(JSON.parse(file).hash)
        )
        //
      ) {
        return next();
      } else {
        res.status(401).json({ error: 'Failed to verify the hmac header' });
      }
    } catch (e) {
      console.log(e);
      return res.status(400).json({ error: 'Something broke this route' });
    }
  };
};

module.exports = hmacVerify;
