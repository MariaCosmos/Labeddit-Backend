import { UserBusiness } from "../business/UserBusiness";
import { LoginInput, SingnupInput } from "../dtos/userDTO";
import { Request, Response } from "express"

export class UserController {
  constructor(
    private userBusiness: UserBusiness
  ){}

  public async signup (req: Request, res: Response){
    try {
      const input: SingnupInput = {
        name: req.body.name,
        email: req.body.email,
        password: req.body.password
      }

      const output = await this.userBusiness.signup(input)

      res.status(201).send(output)
    } catch (error) {
      console.log(error)

      if (req.statusCode === 200) {
        res.status(500)
      }

      if (error instanceof Error) {
        res.send(error.message)
      } else {
        res.send("Erro inesperado")
      }
    }
  }

  public async login (req: Request, res: Response){
    try {
      const input: LoginInput = {
        email: req.body.email,
        password: req.body.password
      }

      const output = await this.userBusiness.login(input)

      res.status(200).send(output)
      
    } catch (error) {
      console.log(error)

      if (req.statusCode === 200) {
        res.status(500)
      }

      if (error instanceof Error) {
        res.send(error.message)
      } else {
        res.send("Erro inesperado")
      }
    }
  }
}