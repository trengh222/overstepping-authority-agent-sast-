<?php

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class SettingsController extends Controller
{
    public function show(Request $request): JsonResponse
    {
        $user = $request->user();

        return response()->json([
            'timezone' => $user->timezone,
            'locale' => $user->locale,
            'email_notifications' => (bool) $user->email_notifications,
        ]);
    }
}
