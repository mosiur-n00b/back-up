const mongoose = require("mongoose");
const bcrypt = require('bcryptjs')
const otpGenerator = require("otp-generator");

const studentSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, "please add a name"],
  },
  email: {
    type: String,
    required: [true, "please add an email"],
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  phone: {
    type: String,
    required: true,
    unique: true,
    validate: {
      validator: function (v) {
        return /^\d{11}$/.test(v);
      },
      message: (props) => `${props.value} is not a valid mobile number!`,
    },
  },
  otp: {
    type: String,
  },
  otpExpiration: {
    type: Date,
  },
  otpRequired: {
    type: Boolean,
    default: true,
  },
  deviceId: {
    type: String,
  },
},
  {
    timestamps: true,
  });

// Match student entered password to hashed password in database
studentSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

// Encrypt password using bcrypt
studentSchema.pre('save', async function (next) {
  if (!this.isModified('password')) {
    next();
  }
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

studentSchema.methods.generateOTP = function () {
  const otp = otpGenerator.generate(6, {
    upperCase: false,
    specialChars: false,
  })
  this.otp = otp
  this.otpExpiration = Date.now() + 2 * 60 * 1000
  return otp
}

studentSchema.methods.verifyOTP = function (enteredOTP) {
  const isValid = this.otp === enteredOTP && this.otpExpiration > Date.now();
  if (!isValid) {
    this.otp = undefined;
    this.otpExpiration = undefined;
  }
  return isValid;
}

studentSchema.methods.setDeviceId = function (deviceId) {
  this.deviceId = deviceId;
};

studentSchema.methods.clearDeviceId = function () {
  this.deviceId = undefined;
};

studentSchema.statics.findByMobileAndPassword = async function (mobile, password, deviceId) {
  const user = await this.findOne({ mobile, password });
  if (!user) {
    return null;
  }
  if (user.deviceId && user.deviceId !== deviceId) {
    throw new Error('User already logged in from another device');
  }
  user.setDeviceId(deviceId);
  await user.save();
  return user;
};

studentSchema.methods.clearOTP = function () {
  this.otp = undefined;
  this.otpExpiration = undefined;
};

studentSchema.methods.logout = async function () {
  this.clearDeviceId();
  await this.save();
};

module.exports = mongoose.model("Student", studentSchema);
