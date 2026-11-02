<?php

namespace App\Http\Controllers;

use App\Models\Document;
use Illuminate\Support\Facades\Auth;

class DocumentController
{
    public function show($id)
    {
        $uid = Auth::id();
        $item = Document::where('id', $id)->where('user_id', $uid)->firstOrFail();
        return response()->json($item);
    }
}
