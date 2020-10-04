const express = require("express");
const router = express.Router();
const { body, validationResult } = require("express-validator");
const gravatar = require("gravatar");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const config = require("config");
const User = require("../../models/User");

// @route GET api/users
// @desc Test route
// @access Public
router.post(
  "/",
  [
    body("name", "Please enter name").not().isEmpty(),
    body("email", "Please enter valid email").isEmail(),
    body(
      "password",
      "please enter password with 6 or more charactors"
    ).isLength({ min: 6 }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const { name, email, password } = req.body;

    try {
      // see if user exists
      let user = await User.findOne({ email: email });
      if (user) {
        return res
          .status(500)
          .json({ errors: [{ msg: "User already exists" }] });
      }

      // user gravatar
      const avatar = gravatar.url(email, {
        s: "200",
        r: "pg",
        d: "mm",
      });

      // new user instance
      user = User({
        name,
        email,
        avatar,
        password,
      });

      // Encrypt Password
      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(password, salt);
      await user.save();

      const payload = {
        user: {
          id: user.id,
        },
      };

      jwt.sign(
        payload,
        config.get("jwtToken"),
        { expiresIn: 360000 },
        (err, token) => {
          if (err) throw err;
          res.json({ token });
        }
      );
    } catch (err) {
      console.error("errors are", err.message);
      res.status(500).send("server error");
    }
  }
);

module.exports = router;
