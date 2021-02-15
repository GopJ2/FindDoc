import {UserModel} from "../UserModel";

export type AuthenticationModel = {
    token: string,
    user: UserModel
}