<?php

namespace App\Http\Controllers;

use App\Models\FileRecord;
use Illuminate\Support\Facades\Auth;

class FileRecordController
{
    public function show($id)
    {
        $uid = Auth::id();
        $item = FileRecord::where('id', $id)->where('user_id', $uid)->firstOrFail();
        return response()->json($item);
    }
}
