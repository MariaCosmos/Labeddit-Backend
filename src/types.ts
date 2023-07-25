export interface UserDB {
  id: string,
  name: string,
  email: string,
  password: string,
  created_at: string
}

export interface TokenPayload {
  id: string,
  name: string,
}  

export interface UserModel {
  id: string,
  name: string,
  email: string,
  password: string,
  createdAt: string
}