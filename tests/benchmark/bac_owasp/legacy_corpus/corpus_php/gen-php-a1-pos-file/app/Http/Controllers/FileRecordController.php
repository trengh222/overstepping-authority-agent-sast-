<?php

namespace App\Http\Controllers;

use App\Models\FileRecord;

class FileRecordController
{
    public function show($id)
    {
        return response()->json(FileRecord::find($id));
    }
}
