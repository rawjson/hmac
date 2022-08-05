const { createHmac, timingSafeEqual } = require('node:crypto');

const hmacVerify = (req, res, next) => {
  try {
    //
    // ----> here we generate a hash using our secret key
    //
    const generatedHash = createHmac('sha256', process.env.SECRET)
      .update(JSON.stringify(req.body))
      .digest('base64');

    // ---->  extract the hash available in request header
    const hashInHeader = req.headers['x-hash-in-header'];

    if (
      // ----> compares without leaking timing info
      //  -    could allow an attacker to guess one of
      //  -    the values otherwise
      timingSafeEqual(Buffer.from(generatedHash), Buffer.from(hashInHeader))
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

module.exports = hmacVerify;
