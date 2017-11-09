%Autor: Cleber Peter

%função converte de string hexadecimal para um array binário
function output_bin = convert_to_bin(in_hex)
    for i=0:((size(in_hex,2)/2) -1)
        output_bin(1,(1:8)+8*i) = de2bi(hex2dec(in_hex(1,(1:2)+2*i)),8,'left-msb');
    end
end