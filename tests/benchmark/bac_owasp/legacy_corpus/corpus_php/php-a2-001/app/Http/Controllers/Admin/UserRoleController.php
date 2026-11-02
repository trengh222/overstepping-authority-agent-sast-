<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class UserRoleController extends Controller
{
    public function update(Request $request, string $id): JsonResponse
    {
        $user = User::findOrFail($id);
        $user->role = $request->input('role');
        $user->save();

        return response()->json([
            'id' => $user->id,
            'role' => $user->role,
        ]);
    }
}
