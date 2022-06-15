int main(){
	puts("\n=== Welcome to the Notepad ===\n");
  printf(1, "How many notes you plan to use? (0-10): ");
  totalNote = get_int();
  if ( totalNote > 10 ) // jg 10
  {
    puts("Bye");
    exit(0);
  }

  idx = 0

  while ( 1 )
  {
    printf("  1. add note
              2. delete note
              3. view notes (%ld/%d)
              4. exit
              >", idx, totalNote);
    option = get_int();

    // 3. view note
    if ( option == 3 )
    {
      printf("note id: ");
      node_idx = get_int();
      v12 = (const char *)ptr[node_idx];
      if ( idx <= node_idx || !v12 )
        v12 = "No such note.\n";
      puts(v12);
    }

    // 4. exit
    if ( option == 4 )
    {
      puts("Thank you for calling. Bye.");
      exit(0);
    }

    // 1. add note
    if ( option == 1 )
    {
      if ( totalNote <= idx )
        puts("Number of notes exceeded.\n");
      else
      {
        printf("size: ");
        size = (int)get_int();
        if ( size-1 > 0xFF )
          puts("Allowed note size: 1 - 256 bytes\n");
        else
        {
          data_chunk = malloc(size);
          ptr[idx] = data_chunk;
          if ( data_chunk )
          {
            printf("content: ");
            read(0, data_chunk, size);
            printf("note %ld added!\n", idx);
          }
          ++idx;
        }
      }
    }

    // 2. del note
    if ( option == 2 )
    {
      printf("note id: ");
      note_id = get_int();
      if (note_id <= idx && ptr[note_id] != 0)
      {
        free(ptr[note_id]);
        printf("note %ld deleted!\n", note_id);
      }
      else
        puts("No such note.");
    }

    else
       puts("huh?");
  }
}
/*

1.add note
2.del note
3.view note
4.exit
-------------
idx = 0
1. add:
- input: size // 1 - 256 bytes
totalNote <= idx:
  chunk = malloc(size) 
  ptr[idx] = chunk
  idx++

2. delete:
-input: node_id
  free(ptr[note_id])) // not null to ptr[note_id] => UAF bug
  
3. view:
- input: node_idx
  if(idx > node_idx and ptr[node_idx] not null):
    puts(ptr[node_idx])
*/