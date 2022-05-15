<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function register(Request $request){
        $fields = $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|unique:users,email',
            'password' => 'required|string|confirmed',
        ]);
        // $request->validate([
        //     'name' => 'required|string|max:255',
        //     'email' => 'required|string|email|max:255|unique:users',
        //     'password' => 'required|string|min:6',
        // ]);
        $user = User::create([
            'name' => $fields['name'],
            'email' => $fields['email'],
            'password' => Hash::make($fields['password']),
        ]);
        // $token = $user->createToken('authToken')->accessToken;
        $token = $user->createToken('authToken')->plainTextToken;

        // return response(['user' => $user, 'token' => $token]);

        $response = [
            'user' => $user,
            'token' => $token,
        ];
        return response($response, 201);
    }


        public function login(Request $request){
        $fields = $request->validate([
            'email' => 'required|string',
            'password' => 'required|string',
        ]);
        // Check Email
        $user = User::where('email', $fields['email'])->first();
        //Check Password
        if (!$user || !Hash::check($fields['password'], $user->password)) {
            return response(['message' => 'Invalid credentials'], 401);
        }

        $token = $user->createToken('authToken')->plainTextToken;

        $response = [
            'user' => $user,
            'token' => $token,
        ];
        return response($response, 201);
    }

    public function logout(Request $request){
        auth()->user()->tokens()->delete();
        return ['message' => 'Successfully logged out'];


        // auth()->user()->tokens->each(function ($token, $key) {
        //     $token->delete();
        // });
        // return response('Logged out', 200);


        // $request->user()->token()->revoke();
        // return response()->json(['message' => 'Successfully logged out']);
    }
}
