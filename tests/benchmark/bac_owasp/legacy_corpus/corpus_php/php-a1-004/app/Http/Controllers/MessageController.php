<?php

namespace App\Http\Controllers;

use App\Models\Message;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class MessageController extends Controller
{
    public function index(Request $request): JsonResponse
    {
        $ownerId = $request->query('owner_id');

        $messages = Message::where('owner_id', $ownerId)->orderByDesc('id')->get();

        return response()->json($messages->map(function (Message $message) {
            return [
                'id' => $message->id,
                'subject' => $message->subject,
                'created_at' => $message->created_at,
            ];
        }));
    }
}
