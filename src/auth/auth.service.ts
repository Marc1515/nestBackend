import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';

import * as bcryptjs from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './intarfaces/jwt-payload';

import { CreateUserDto, LoginDTO, RegisterUserDto, UpdateAuthDto } from './dto';

import { User } from './entities/user.entity';
import { LoginResponse } from './intarfaces/login-response';


@Injectable()
export class AuthService {

  constructor(
    @InjectModel( User.name )
    private userModel: Model<User>,
    private jwtService: JwtService
  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    

    try {

      const { password, ...userData } = createUserDto;

      // 1 - Ectriptar la contraseña

      const newUser = new this.userModel({
        password: bcryptjs.hashSync( password, 10 ),
        ...userData
      })


      // 2 - Guardar el usuario

      await newUser.save();
      const { password:_, ...user } = newUser.toJSON();

      return user;

      // 3 - Generar JWT


      
    } catch (error) {
      if( error.code === 11000 ) {
        throw new BadRequestException(`${ createUserDto.email } already exist!`);
      }
      throw new InternalServerErrorException('Something terrible happen!')
    }

  }

  async register( registerDto: RegisterUserDto ): Promise<LoginResponse> {
    const user = await this.create( registerDto );
    console.log({user})

    return {
      user: user,
      token: this.getJwtToken({ id: user._id })
    }

  }

  async login( loginDto: LoginDTO ) {
    
    const { email, password } = loginDto;

    const user = await this.userModel.findOne({ email: email });

    if (!user) {
      throw new UnauthorizedException('Not valid credentials - email')
    }

    if ( !bcryptjs.compareSync( password, user.password ) ) {
      throw new UnauthorizedException('Not valid credentials - password')
    }

    const { password:_, ...rest } = user.toJSON();

    return {
      user: rest,
      token: this.getJwtToken({ id: user.id })
    };

  }

  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  async findUserById( id: string ) {
    const user = await this.userModel.findById(id);
    const { password, ...rest } = user.toJSON();

    return rest;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwtToken( payload: JwtPayload ) {
    const token = this.jwtService.sign(payload);
    return token;
  }
}
