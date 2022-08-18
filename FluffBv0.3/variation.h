#ifndef VARIATION_H
#define VARIATION_H

#include "headers.h"

void Order(unsigned (*d1),unsigned (*d2))
{
    if((*d1)>(*d2))
    {
        (*d1)=(*d1)^(*d2);
        (*d2)=(*d1)^(*d2);
        (*d1)=(*d1)^(*d2);
    }
}

void ZeroMemory(void*tar,unsigned size)
{
    memset(tar,0,size);
}

unsigned RandomVariation(char*data,unsigned len)
{
    //srand(time(0));
    switch (rand()%12)
    {
        //1 bit flip
        case 0:
        {
            srand(time(0));
            unsigned byte = rand()%len;
            srand(time(0));
            unsigned bit = rand()%8;
            *(data+byte)^=((char)(1<<bit));
            break;
        }
        //2 bits flip
        case 1:
        {
            srand(time(0));
            unsigned byte = rand()%len;
            srand(time(0));
            unsigned bit = rand()%7;
            *(data+byte)^=((char)(0x03<<bit));
            break;
        }
        //4 bits flip
        case 2:
        {
            srand(time(0));
            unsigned byte = rand()%len;
            srand(time(0));
            unsigned bit = rand()%5;
            *(data+byte)^=((char)(0x0F<<bit));
            break;
        }
        //1 byte flip
        case 3:
        {
            srand(time(0));
            unsigned byte = rand()%len;
            *(data+byte)^=((char)(0xFF));
            break;
        }
        //2 bytes flip
        case 4:
        {
            srand(time(0));
            unsigned byte = rand()%len;
            *((short*)(data+byte))^=((short)(0xFFFF));
            break;
        }
        //4 bytes flip
        case 5:
        {
            srand(time(0));
            unsigned byte = rand()%len;
            *((int*)(data+byte))^=((int)(0xFFFFFFFF));
            break;
        }
        //1 byte replace
        case 6:
        {
            srand(time(0));
            unsigned byte = rand()%len;
            srand(time(0));
            char tar=rand()%(1<<8);
            *((char*)(data+byte))=tar;
            break;
        }
        //2 bytes replace
        case 7:
        {
            srand(time(0));
            unsigned byte = rand()%len;
            srand(time(0));
            short tar=rand()%(1<<16);
            *((short*)(data+byte))=tar;
            break;
        }
        //4 bytes replace
        case 8:
        {
            srand(time(0));
            unsigned byte = rand()%len;
            srand(time(0));
            int tar=rand();
            *((int*)(data+byte))=tar;
            break;
        }
        //delete a piece
        case 9:
        {
            srand(time(0));
            unsigned byte0 = rand()%len;
            usleep(50);
            srand(time(0));
            unsigned byte1 = rand()%len;
            Order(&byte0,&byte1);
            memcpy(data+byte0,data+byte1,len-byte1);
            len=len-(byte1-byte0);
            break;
        }
        //set a piece to 0
        case 10:
        {
            srand(time(0));
            unsigned byte0 = rand()%len;
            usleep(50);
            srand(time(0));
            unsigned byte1 = rand()%len;
            ZeroMemory(data+byte0,byte1-byte0);
            break;
        }
        case 11:
        {
            break;
        }
    }
    return len;
}

#endif