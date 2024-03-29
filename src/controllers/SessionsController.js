const AppError = require("../utils/AppError")
const { compare } = require("bcryptjs")

const authConfig = require("../configs/auth")
const { sign } = require("jsonwebtoken")

class SessionsController {
  async create(request, response) {
    const { email, password } = request.body

    const user = await knex("users").where({ email }).first()

    if(!user) {
      throw new AppError("E-mail e/ou senha incorreta", 401)
    }

    // compare(senha digitada com a senha que tá no banco de dados)
    const passwordMatched = await compare(password, user.password)

    if(!passwordMatched) {
      throw new AppError("E-mail e/ou senha incorreta", 401)
    }

    const { secret, expiresIn } = authConfig.jwt
    const token = sign({}, secret, {
      subject: String(user.id),
      expiresIn
    })

    // Pra senha não aparecer no localStorage:
    return response.json({
      user: {
        ...user,
        password: undefined,
      },
      token,
    });
  }
}

module.exports = SessionsController